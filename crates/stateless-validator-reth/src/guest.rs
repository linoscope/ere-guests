//! [`Guest`] implementation for Reth stateless validator.

use alloc::{format, sync::Arc, vec, vec::Vec};

use alethia_reth_block::config::TaikoEvmConfig;
use alethia_reth_chainspec::{hardfork::TaikoHardfork, spec::TaikoChainSpec};
use alloy_genesis::ChainConfig;
use alloy_hardforks::{EthereumHardfork, ForkCondition, Hardfork};
use alloy_primitives::U256;
use guest::codec::impl_codec_by_bincode_legacy;
use reth_chainspec::ChainSpec;
use reth_ethereum_forks::ChainHardforks;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use stateless::{ExecutionWitness, Genesis, UncompressedPublicKey, stateless_validation_with_trie};
use stateless_validator_common::new_payload_request::{NewPayloadRequest, Sha256Hasher};
use tries::zeth::SparseState;

use crate::new_payload_request::new_payload_request_to_block;

#[rustfmt::skip]
pub use {
    guest::*,
    stateless_validator_common::{guest::StatelessValidatorOutput, new_payload_request},
};

#[cfg(feature = "openvm")]
mod openvm;
#[cfg(feature = "zisk")]
mod zisk;

/// Input for the stateless validator guest program.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatelessValidatorRethInput {
    /// New payload request data.
    pub new_payload_request: NewPayloadRequest,
    /// Execution witness for the EL block.
    pub witness: ExecutionWitness,
    /// Chain configuration for the stateless validation function
    #[serde_as(as = "alloy_genesis::serde_bincode_compat::ChainConfig<'_>")]
    pub chain_config: ChainConfig,
    /// The recovered signers for the transactions in the block.
    pub public_keys: Vec<UncompressedPublicKey>,
}

impl_codec_by_bincode_legacy!(StatelessValidatorRethInput);

/// [`Guest`] implementation for Reth stateless validator.
#[derive(Debug, Clone)]
pub struct StatelessValidatorRethGuest;

impl Guest for StatelessValidatorRethGuest {
    type Input = StatelessValidatorRethInput;
    type Output = StatelessValidatorOutput;

    fn compute<P: Platform>(input: Self::Input) -> Self::Output {
        let new_payload_request_root =
            P::cycle_scope("new_payload_request_root_calculation", || {
                input.new_payload_request.tree_hash_root(&sha256_hasher())
            });

        #[cfg(feature = "std")]
        {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                Self::compute_inner::<P>(input, new_payload_request_root)
            }));

            match result {
                Ok(output) => output,
                Err(_) => {
                    P::print("Panic occurred during validation\n");
                    StatelessValidatorOutput::new(new_payload_request_root, false)
                }
            }
        }

        #[cfg(not(feature = "std"))]
        {
            Self::compute_inner::<P>(input, new_payload_request_root)
        }
    }
}

impl StatelessValidatorRethGuest {
    fn compute_inner<P: Platform>(
        input: GuestInput<Self>,
        new_payload_request_root: [u8; 32],
    ) -> GuestOutput<Self> {
        let (chain_spec, evm_config) = P::cycle_scope("misc_preparation", || {
            let chain_id = input.chain_config.chain_id;
            let genesis = Genesis {
                config: input.chain_config.clone(),
                ..Default::default()
            };

            // Activate TaikoHardfork::Unzen at timestamp 0 so the ZkGasInspector fires for
            // every opcode. We deliberately leave EthereumHardfork::Osaka inactive — Unzen
            // selects Osaka semantics in revm, but `is_osaka_active_at_timestamp` is what
            // gates the 30M tx-gas-limit cap in TaikoEvmConfig::evm_env, and our stress
            // fixtures use 50M per-tx limits.
            let block0 = ForkCondition::Block(0);
            let ts0 = ForkCondition::Timestamp(0);
            let hardforks = ChainHardforks::new(vec![
                (EthereumHardfork::Frontier.boxed(), block0),
                (EthereumHardfork::Homestead.boxed(), block0),
                (EthereumHardfork::Tangerine.boxed(), block0),
                (EthereumHardfork::SpuriousDragon.boxed(), block0),
                (EthereumHardfork::Byzantium.boxed(), block0),
                (EthereumHardfork::Constantinople.boxed(), block0),
                (EthereumHardfork::Petersburg.boxed(), block0),
                (EthereumHardfork::Istanbul.boxed(), block0),
                (EthereumHardfork::MuirGlacier.boxed(), block0),
                (EthereumHardfork::Berlin.boxed(), block0),
                (EthereumHardfork::London.boxed(), block0),
                (EthereumHardfork::ArrowGlacier.boxed(), block0),
                (EthereumHardfork::GrayGlacier.boxed(), block0),
                (
                    EthereumHardfork::Paris.boxed(),
                    ForkCondition::TTD {
                        activation_block_number: 0,
                        fork_block: Some(0),
                        total_difficulty: U256::ZERO,
                    },
                ),
                (EthereumHardfork::Shanghai.boxed(), ts0),
                (EthereumHardfork::Cancun.boxed(), ts0),
                (EthereumHardfork::Prague.boxed(), ts0),
                (TaikoHardfork::Ontake.boxed(), block0),
                (TaikoHardfork::Pacaya.boxed(), block0),
                (TaikoHardfork::Shasta.boxed(), ts0),
                (TaikoHardfork::Unzen.boxed(), ts0),
            ]);

            let inner = ChainSpec::builder()
                .chain(chain_id.into())
                .genesis(genesis)
                .with_forks(hardforks)
                .build();
            let chain_spec = Arc::new(TaikoChainSpec { inner });
            let evm_config = TaikoEvmConfig::new(chain_spec.clone());
            (chain_spec, evm_config)
        });

        let block_result: anyhow::Result<_> =
            P::cycle_scope("new_payload_request_to_block", || {
                let sealed_block =
                    new_payload_request_to_block(input.new_payload_request, chain_spec.clone())?;
                // TODO: consider asking Reth to have an `stateless_validation_with_trie`
                // variant which accepts `SealedBlock`. Since this isn't the case today,
                // `stateless_validator_with_trie` will hash again the block.
                Ok(sealed_block.into_block())
            });

        let block = match block_result {
            Ok(block) => block,
            Err(err) => {
                P::print(&format!("Failed to convert to reth block: {err}\n"));
                return StatelessValidatorOutput::new(new_payload_request_root, false);
            }
        };

        let res = P::cycle_scope("stf", || {
            stateless_validation_with_trie::<SparseState, _, _>(
                block,
                input.public_keys,
                input.witness,
                chain_spec,
                evm_config,
            )
        });

        match res {
            Ok(_) => StatelessValidatorOutput::new(new_payload_request_root, true),
            Err(err) => {
                P::print(&format!("Block validation failed: {err}\n"));
                StatelessValidatorOutput::new(new_payload_request_root, false)
            }
        }
    }
}

#[allow(unreachable_code)]
fn sha256_hasher() -> impl Sha256Hasher {
    #[cfg(feature = "openvm")]
    return openvm::OpenVMSha256Hasher;
    #[cfg(feature = "zisk")]
    return zisk::ZiskSha256Hasher;
    #[cfg(not(any(feature = "openvm", feature = "zisk")))]
    return stateless_validator_common::new_payload_request::NativeSha256Hasher;
}
