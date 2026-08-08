//! AIVM bytecode format tests

use aivm::bytecode::{BytecodeArtifact, BytecodeHeader, Section, MAGIC, HEADER_SIZE, section_type, BYTECODE_VERSION, AIVM_VERSION};
use aivm::instructions::{Instruction, Opcode};
use aivm::abi::{Abi, AbiType, AbiMethod};

#[test]
fn test_header_roundtrip() {
    let header = BytecodeHeader {
        magic: MAGIC,
        bytecode_version: BYTECODE_VERSION,
        target_aivm_version: AIVM_VERSION,
        abi_hash: [1u8; 32],
        manifest_hash: [2u8; 32],
        code_hash: [3u8; 32],
        section_count: 1,
    };
    let encoded = header.encode();
    assert_eq!(encoded.len(), HEADER_SIZE);
    let decoded = BytecodeHeader::decode(&encoded).unwrap();
    assert_eq!(header, decoded);
}

#[test]
fn test_bad_magic_rejected() {
    let mut header_bytes = BytecodeHeader {
        magic: MAGIC,
        bytecode_version: BYTECODE_VERSION,
        target_aivm_version: AIVM_VERSION,
        abi_hash: [0u8; 32],
        manifest_hash: [0u8; 32],
        code_hash: [0u8; 32],
        section_count: 0,
    }.encode();
    header_bytes[0] = b'X';
    assert!(BytecodeHeader::decode(&header_bytes).is_err());
}

#[test]
fn test_artifact_roundtrip() {
    let instructions = vec![
        Instruction::PushU64(42),
        Instruction::Ret,
    ];
    let instruction_bytes = Instruction::encode_all(&instructions);
    let code_hash = BytecodeArtifact::compute_code_hash(&instruction_bytes);

    let header = BytecodeHeader {
        magic: MAGIC,
        bytecode_version: BYTECODE_VERSION,
        target_aivm_version: AIVM_VERSION,
        abi_hash: [0u8; 32],
        manifest_hash: [0u8; 32],
        code_hash,
        section_count: 1,
    };
    let artifact = BytecodeArtifact {
        header,
        sections: vec![Section {
            section_type: section_type::INSTRUCTIONS,
            data: instruction_bytes.clone(),
        }],
    };

    let encoded = artifact.encode();
    let decoded = BytecodeArtifact::decode(&encoded).unwrap();
    assert_eq!(decoded.header, artifact.header);
    assert_eq!(decoded.sections.len(), 1);
    assert_eq!(decoded.sections[0].data, instruction_bytes);
}

#[test]
fn test_code_hash_validation() {
    let instructions = vec![Instruction::Nop, Instruction::Ret];
    let instruction_bytes = Instruction::encode_all(&instructions);
    let code_hash = BytecodeArtifact::compute_code_hash(&instruction_bytes);

    let mut artifact = BytecodeArtifact {
        header: BytecodeHeader {
            magic: MAGIC,
            bytecode_version: BYTECODE_VERSION,
            target_aivm_version: AIVM_VERSION,
            abi_hash: [0u8; 32],
            manifest_hash: [0u8; 32],
            code_hash,
            section_count: 1,
        },
        sections: vec![Section {
            section_type: section_type::INSTRUCTIONS,
            data: instruction_bytes,
        }],
    };

    // Tamper with code hash
    artifact.header.code_hash = [0xFF; 32];
    let encoded = artifact.encode();
    assert!(BytecodeArtifact::decode(&encoded).is_err());
}

#[test]
fn test_duplicate_section_rejected() {
    let instructions = Instruction::encode_all(&[Instruction::Ret]);
    let code_hash = BytecodeArtifact::compute_code_hash(&instructions);
    let artifact = BytecodeArtifact {
        header: BytecodeHeader {
            magic: MAGIC,
            bytecode_version: BYTECODE_VERSION,
            target_aivm_version: AIVM_VERSION,
            abi_hash: [0u8; 32],
            manifest_hash: [0u8; 32],
            code_hash,
            section_count: 2,
        },
        sections: vec![
            Section { section_type: section_type::INSTRUCTIONS, data: instructions.clone() },
            Section { section_type: section_type::INSTRUCTIONS, data: vec![] },
        ],
    };
    let encoded = artifact.encode();
    assert!(BytecodeArtifact::decode(&encoded).is_err());
}

#[test]
fn test_instruction_encode_decode_roundtrip() {
    let instructions = vec![
        Instruction::Nop,
        Instruction::PushU64(0xDEADBEEF),
        Instruction::PushBytes(vec![1, 2, 3, 4, 5]),
        Instruction::LoadState(5),
        Instruction::StoreState(10),
        Instruction::LoadLocal(3),
        Instruction::StoreLocal(7),
        Instruction::AddU64,
        Instruction::SubU64,
        Instruction::MulU64,
        Instruction::DivU64,
        Instruction::Eq,
        Instruction::Lt,
        Instruction::Gt,
        Instruction::Jmp(100),
        Instruction::JmpIf(200),
        Instruction::Call(42),
        Instruction::Ret,
        Instruction::Emit(3),
        Instruction::Trap(1),
        Instruction::HostCall(5),
    ];

    let encoded = Instruction::encode_all(&instructions);
    let decoded = Instruction::decode_all(&encoded).unwrap();
    assert_eq!(instructions, decoded);
}

#[test]
fn test_unknown_opcode_rejected() {
    let bytes = vec![0xFF]; // unknown opcode
    assert!(Instruction::decode_all(&bytes).is_err());
}
