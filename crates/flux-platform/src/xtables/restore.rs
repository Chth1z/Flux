use std::error::Error;
use std::fmt;
use std::net::IpAddr;

use sha2::{Digest, Sha256};

pub const XTABLES_RESTORE_SCHEMA_VERSION: u16 = 1;
pub const XTABLES_RESTORE_DIGEST_BYTES: usize = 32;

pub const MAX_XTABLES_RESTORE_BYTES: usize = 1024 * 1024;
pub const MAX_XTABLES_RESTORE_LINES: usize = 32_768;
pub const MAX_XTABLES_RESTORE_LINE_BYTES: usize = 4096;
pub const MAX_XTABLES_RESTORE_TRANSACTIONS: usize = 64;
pub const MAX_XTABLES_RESTORE_COMMANDS: usize = 16_384;
pub const MAX_XTABLES_RESTORE_TOKENS_PER_COMMAND: usize = 256;
pub const MAX_XTABLES_RESTORE_TOKEN_BYTES: usize = 255;
pub const MAX_XTABLES_RESTORE_CHAIN_BYTES: usize = 28;

const XTABLES_RESTORE_DIGEST_DOMAIN: &[u8] =
    b"Flux observed xtables restore artifact\0canonical-schema-v1\0";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum XtablesRestoreAction {
    Apply,
    /// Atomically replace the contents of already-owned user chains.
    ///
    /// Canonical replace artifacts flush one or more chains first and then
    /// append their complete new contents. They cannot create chains, edit
    /// built-in hooks, delete rules, or delete chains.
    Replace,
    Cleanup,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum XtablesRestoreFamily {
    Ipv4,
    Ipv6,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct XtablesRestoreContext {
    action: XtablesRestoreAction,
    family: XtablesRestoreFamily,
}

impl XtablesRestoreContext {
    #[must_use]
    pub const fn new(action: XtablesRestoreAction, family: XtablesRestoreFamily) -> Self {
        Self { action, family }
    }

    #[must_use]
    pub const fn action(self) -> XtablesRestoreAction {
        self.action
    }

    #[must_use]
    pub const fn family(self) -> XtablesRestoreFamily {
        self.family
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum XtablesRestoreTable {
    Mangle,
    Filter,
    Nat,
}

impl XtablesRestoreTable {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Mangle => "mangle",
            Self::Filter => "filter",
            Self::Nat => "nat",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum XtablesRestoreCommandKind {
    Append,
    Insert,
    Delete,
    Flush,
    DeleteChain,
}

impl XtablesRestoreCommandKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Append => "-A",
            Self::Insert => "-I",
            Self::Delete => "-D",
            Self::Flush => "-F",
            Self::DeleteChain => "-X",
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct XtablesRestoreToken(Box<str>);

impl XtablesRestoreToken {
    #[must_use]
    pub const fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XtablesChainDeclaration {
    chain: Box<str>,
}

impl XtablesChainDeclaration {
    #[must_use]
    pub const fn chain(&self) -> &str {
        &self.chain
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XtablesRestoreCommand {
    kind: XtablesRestoreCommandKind,
    chain: Box<str>,
    arguments: Box<[XtablesRestoreToken]>,
}

impl XtablesRestoreCommand {
    #[must_use]
    pub const fn kind(&self) -> XtablesRestoreCommandKind {
        self.kind
    }

    #[must_use]
    pub const fn chain(&self) -> &str {
        &self.chain
    }

    #[must_use]
    pub const fn arguments(&self) -> &[XtablesRestoreToken] {
        &self.arguments
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum XtablesRestoreEntry {
    ChainDeclaration(XtablesChainDeclaration),
    Command(XtablesRestoreCommand),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XtablesRestoreTransaction {
    table: XtablesRestoreTable,
    entries: Box<[XtablesRestoreEntry]>,
}

impl XtablesRestoreTransaction {
    #[must_use]
    pub const fn table(&self) -> XtablesRestoreTable {
        self.table
    }

    #[must_use]
    pub const fn entries(&self) -> &[XtablesRestoreEntry] {
        &self.entries
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct XtablesRestoreDigest([u8; XTABLES_RESTORE_DIGEST_BYTES]);

impl XtablesRestoreDigest {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; XTABLES_RESTORE_DIGEST_BYTES] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XtablesRestoreResourceUsage {
    input_bytes: usize,
    lines: usize,
    transactions: usize,
    chain_declarations: usize,
    commands: usize,
    tokens: usize,
}

impl XtablesRestoreResourceUsage {
    #[must_use]
    pub const fn input_bytes(self) -> usize {
        self.input_bytes
    }

    #[must_use]
    pub const fn lines(self) -> usize {
        self.lines
    }

    #[must_use]
    pub const fn transactions(self) -> usize {
        self.transactions
    }

    #[must_use]
    pub const fn chain_declarations(self) -> usize {
        self.chain_declarations
    }

    #[must_use]
    pub const fn commands(self) -> usize {
        self.commands
    }

    /// Returns lexical declaration and command tokens. Table opens and `COMMIT` are lines, not
    /// tokens in the closed restore grammar.
    #[must_use]
    pub const fn tokens(self) -> usize {
        self.tokens
    }
}

/// Parsed, observation-only restore bytes.
///
/// This type carries no Generation identity, writer ownership, execution capability, prepared or
/// active state, or conversion into any runtime mutation path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XtablesRestoreArtifact {
    schema_version: u16,
    context: XtablesRestoreContext,
    transactions: Box<[XtablesRestoreTransaction]>,
    digest: XtablesRestoreDigest,
    usage: XtablesRestoreResourceUsage,
}

impl XtablesRestoreArtifact {
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    #[must_use]
    pub const fn context(&self) -> XtablesRestoreContext {
        self.context
    }

    #[must_use]
    pub const fn transactions(&self) -> &[XtablesRestoreTransaction] {
        &self.transactions
    }

    #[must_use]
    pub const fn digest(&self) -> XtablesRestoreDigest {
        self.digest
    }

    #[must_use]
    pub const fn usage(&self) -> XtablesRestoreResourceUsage {
        self.usage
    }

    #[must_use]
    pub fn render_canonical(&self) -> Box<[u8]> {
        render_transactions(&self.transactions, self.usage.input_bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XtablesRestoreLimit {
    Bytes,
    Lines,
    LineBytes,
    Transactions,
    Commands,
    TokensPerCommand,
    TokenBytes,
    ChainBytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XtablesRestoreParseErrorKind {
    EmptyInput,
    LimitExceeded {
        resource: XtablesRestoreLimit,
        maximum: usize,
        actual: usize,
    },
    NonCanonicalByte {
        offset: usize,
        byte: u8,
    },
    MissingFinalLineFeed,
    EmptyLine,
    NonCanonicalSpacing,
    ContentOutsideTransaction,
    UnknownTable,
    NestedTransaction,
    UnterminatedTransaction,
    EmptyTransaction {
        table: XtablesRestoreTable,
    },
    InvalidChainDeclaration,
    ChainDeclarationNotAllowed,
    ChainDeclarationTableMismatch {
        table: XtablesRestoreTable,
    },
    ChainDeclarationAfterCommand,
    InvalidChainName,
    UnsupportedCommand,
    InvalidCommandArity {
        command: XtablesRestoreCommandKind,
    },
    ActionMismatch {
        action: XtablesRestoreAction,
        command: XtablesRestoreCommandKind,
    },
    CommandTableMismatch {
        table: XtablesRestoreTable,
        command: XtablesRestoreCommandKind,
    },
    PositionalInsertNotSupported,
    PositionalDeleteNotSupported,
    InvalidToken,
    UnsupportedRuleOption,
    MissingOptionValue,
    InvalidJumpTarget,
    UnsupportedProtocol,
    InvalidAddress,
    FamilyMismatch {
        expected: XtablesRestoreFamily,
    },
    CleanupOrdering {
        command: XtablesRestoreCommandKind,
    },
    ReplaceOrdering {
        command: XtablesRestoreCommandKind,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XtablesRestoreParseError {
    line: Option<usize>,
    kind: XtablesRestoreParseErrorKind,
}

impl XtablesRestoreParseError {
    #[must_use]
    pub const fn line(&self) -> Option<usize> {
        self.line
    }

    #[must_use]
    pub const fn kind(&self) -> XtablesRestoreParseErrorKind {
        self.kind
    }

    const fn global(kind: XtablesRestoreParseErrorKind) -> Self {
        Self { line: None, kind }
    }

    const fn at_line(line: usize, kind: XtablesRestoreParseErrorKind) -> Self {
        Self {
            line: Some(line),
            kind,
        }
    }
}

impl fmt::Display for XtablesRestoreParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid canonical xtables restore artifact")?;
        if let Some(line) = self.line {
            write!(formatter, " at line {line}")?;
        }
        write!(formatter, ": {:?}", self.kind)
    }
}

impl Error for XtablesRestoreParseError {}

struct TransactionBuilder {
    table: XtablesRestoreTable,
    entries: Vec<XtablesRestoreEntry>,
    saw_command: bool,
    command_stage: CommandStage,
}

impl TransactionBuilder {
    const fn new(table: XtablesRestoreTable) -> Self {
        Self {
            table,
            entries: Vec::new(),
            saw_command: false,
            command_stage: CommandStage::Initial,
        }
    }

    fn finish(self) -> XtablesRestoreTransaction {
        XtablesRestoreTransaction {
            table: self.table,
            entries: self.entries.into_boxed_slice(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd)]
enum CommandStage {
    Initial,
    Flushing,
    Populating,
    DeletingChains,
}

/// Parse canonical restore bytes without performing filesystem, process, or kernel I/O.
pub fn parse_xtables_restore(
    input: &[u8],
    context: XtablesRestoreContext,
) -> Result<XtablesRestoreArtifact, XtablesRestoreParseError> {
    validate_document_bytes(input)?;

    let line_count = input.iter().filter(|byte| **byte == b'\n').count();
    ensure_limit(
        XtablesRestoreLimit::Lines,
        MAX_XTABLES_RESTORE_LINES,
        line_count,
    )?;

    let text = std::str::from_utf8(input).expect("validated ASCII is valid UTF-8");
    let mut transactions = Vec::new();
    let mut current = None;
    let mut chain_declarations = 0usize;
    let mut commands = 0usize;
    let mut tokens = 0usize;

    for (line_index, line) in text[..text.len() - 1].split('\n').enumerate() {
        let line_number = line_index + 1;
        validate_line_shape(line, line_number)?;

        if current.is_none() {
            let table = parse_table_open(line, line_number)?;
            ensure_line_limit(
                line_number,
                XtablesRestoreLimit::Transactions,
                MAX_XTABLES_RESTORE_TRANSACTIONS,
                transactions.len() + 1,
            )?;
            current = Some(TransactionBuilder::new(table));
            continue;
        }

        if line == "COMMIT" {
            let transaction = current.take().expect("transaction checked above");
            if transaction.entries.is_empty() && transaction.table != XtablesRestoreTable::Mangle {
                return Err(XtablesRestoreParseError::at_line(
                    line_number,
                    XtablesRestoreParseErrorKind::EmptyTransaction {
                        table: transaction.table,
                    },
                ));
            }
            transactions.push(transaction.finish());
            continue;
        }

        if line.starts_with('*') {
            return Err(XtablesRestoreParseError::at_line(
                line_number,
                XtablesRestoreParseErrorKind::NestedTransaction,
            ));
        }

        let transaction = current.as_mut().expect("transaction checked above");
        if line.starts_with(':') {
            parse_chain_declaration(line, line_number, context, transaction)?;
            chain_declarations += 1;
            tokens += 3;
        } else if line.starts_with('-') {
            ensure_line_limit(
                line_number,
                XtablesRestoreLimit::Commands,
                MAX_XTABLES_RESTORE_COMMANDS,
                commands + 1,
            )?;
            let command = parse_command(
                line,
                line_number,
                context,
                transaction.table,
                transaction.command_stage,
            )?;
            transaction.saw_command = true;
            transaction.command_stage =
                command_stage_after(context.action, transaction.command_stage, command.kind);
            tokens += 2 + command.arguments.len();
            commands += 1;
            transaction
                .entries
                .push(XtablesRestoreEntry::Command(command));
        } else {
            return Err(XtablesRestoreParseError::at_line(
                line_number,
                XtablesRestoreParseErrorKind::ContentOutsideTransaction,
            ));
        }
    }

    if current.is_some() {
        return Err(XtablesRestoreParseError::at_line(
            line_count,
            XtablesRestoreParseErrorKind::UnterminatedTransaction,
        ));
    }

    let usage = XtablesRestoreResourceUsage {
        input_bytes: input.len(),
        lines: line_count,
        transactions: transactions.len(),
        chain_declarations,
        commands,
        tokens,
    };
    let transactions = transactions.into_boxed_slice();
    debug_assert_eq!(
        render_transactions(&transactions, input.len()).as_ref(),
        input
    );
    let digest = digest_restore(context, input);

    Ok(XtablesRestoreArtifact {
        schema_version: XTABLES_RESTORE_SCHEMA_VERSION,
        context,
        transactions,
        digest,
        usage,
    })
}

fn validate_document_bytes(input: &[u8]) -> Result<(), XtablesRestoreParseError> {
    if input.is_empty() {
        return Err(XtablesRestoreParseError::global(
            XtablesRestoreParseErrorKind::EmptyInput,
        ));
    }
    ensure_limit(
        XtablesRestoreLimit::Bytes,
        MAX_XTABLES_RESTORE_BYTES,
        input.len(),
    )?;
    if input.last() != Some(&b'\n') {
        return Err(XtablesRestoreParseError::global(
            XtablesRestoreParseErrorKind::MissingFinalLineFeed,
        ));
    }
    for (offset, byte) in input.iter().copied().enumerate() {
        if byte != b'\n' && !(b' '..=b'~').contains(&byte) {
            return Err(XtablesRestoreParseError::global(
                XtablesRestoreParseErrorKind::NonCanonicalByte { offset, byte },
            ));
        }
    }
    Ok(())
}

fn validate_line_shape(line: &str, line_number: usize) -> Result<(), XtablesRestoreParseError> {
    if line.is_empty() {
        return Err(XtablesRestoreParseError::at_line(
            line_number,
            XtablesRestoreParseErrorKind::EmptyLine,
        ));
    }
    ensure_line_limit(
        line_number,
        XtablesRestoreLimit::LineBytes,
        MAX_XTABLES_RESTORE_LINE_BYTES,
        line.len(),
    )?;
    if line.starts_with(' ')
        || line.ends_with(' ')
        || line.as_bytes().windows(2).any(|w| w == b"  ")
    {
        return Err(XtablesRestoreParseError::at_line(
            line_number,
            XtablesRestoreParseErrorKind::NonCanonicalSpacing,
        ));
    }
    Ok(())
}

fn parse_table_open(
    line: &str,
    line_number: usize,
) -> Result<XtablesRestoreTable, XtablesRestoreParseError> {
    match line {
        "*mangle" => Ok(XtablesRestoreTable::Mangle),
        "*filter" => Ok(XtablesRestoreTable::Filter),
        "*nat" => Ok(XtablesRestoreTable::Nat),
        _ if line.starts_with('*') => Err(XtablesRestoreParseError::at_line(
            line_number,
            XtablesRestoreParseErrorKind::UnknownTable,
        )),
        _ => Err(XtablesRestoreParseError::at_line(
            line_number,
            XtablesRestoreParseErrorKind::ContentOutsideTransaction,
        )),
    }
}

fn parse_chain_declaration(
    line: &str,
    line_number: usize,
    context: XtablesRestoreContext,
    transaction: &mut TransactionBuilder,
) -> Result<(), XtablesRestoreParseError> {
    if context.action != XtablesRestoreAction::Apply {
        return Err(XtablesRestoreParseError::at_line(
            line_number,
            XtablesRestoreParseErrorKind::ChainDeclarationNotAllowed,
        ));
    }
    if transaction.table != XtablesRestoreTable::Mangle {
        return Err(XtablesRestoreParseError::at_line(
            line_number,
            XtablesRestoreParseErrorKind::ChainDeclarationTableMismatch {
                table: transaction.table,
            },
        ));
    }
    if transaction.saw_command {
        return Err(XtablesRestoreParseError::at_line(
            line_number,
            XtablesRestoreParseErrorKind::ChainDeclarationAfterCommand,
        ));
    }

    let parts = line.split(' ').collect::<Vec<_>>();
    if parts.len() != 3 || parts[1] != "-" || parts[2] != "[0:0]" {
        return Err(XtablesRestoreParseError::at_line(
            line_number,
            XtablesRestoreParseErrorKind::InvalidChainDeclaration,
        ));
    }
    let chain = parts[0].strip_prefix(':').unwrap_or_default();
    validate_chain(chain, line_number)?;
    validate_chain_family(chain, context.family, line_number)?;
    transaction
        .entries
        .push(XtablesRestoreEntry::ChainDeclaration(
            XtablesChainDeclaration {
                chain: chain.into(),
            },
        ));
    Ok(())
}

fn parse_command(
    line: &str,
    line_number: usize,
    context: XtablesRestoreContext,
    table: XtablesRestoreTable,
    command_stage: CommandStage,
) -> Result<XtablesRestoreCommand, XtablesRestoreParseError> {
    let token_count = line.as_bytes().iter().filter(|byte| **byte == b' ').count() + 1;
    ensure_line_limit(
        line_number,
        XtablesRestoreLimit::TokensPerCommand,
        MAX_XTABLES_RESTORE_TOKENS_PER_COMMAND,
        token_count,
    )?;
    let parts = line.split(' ').collect::<Vec<_>>();
    let kind = match parts[0] {
        "-A" => XtablesRestoreCommandKind::Append,
        "-I" => XtablesRestoreCommandKind::Insert,
        "-D" => XtablesRestoreCommandKind::Delete,
        "-F" => XtablesRestoreCommandKind::Flush,
        "-X" => XtablesRestoreCommandKind::DeleteChain,
        _ => {
            return Err(XtablesRestoreParseError::at_line(
                line_number,
                XtablesRestoreParseErrorKind::UnsupportedCommand,
            ));
        }
    };
    validate_action(context.action, kind, line_number)?;
    validate_command_table(table, kind, line_number)?;
    validate_command_arity(kind, &parts, line_number)?;
    if matches!(
        kind,
        XtablesRestoreCommandKind::Insert | XtablesRestoreCommandKind::Delete
    ) && is_positional_rule_number(parts[2])
    {
        let positional_error = match kind {
            XtablesRestoreCommandKind::Insert => {
                Some(XtablesRestoreParseErrorKind::PositionalInsertNotSupported)
            }
            XtablesRestoreCommandKind::Delete => {
                Some(XtablesRestoreParseErrorKind::PositionalDeleteNotSupported)
            }
            XtablesRestoreCommandKind::Append
            | XtablesRestoreCommandKind::Flush
            | XtablesRestoreCommandKind::DeleteChain => None,
        };
        if let Some(kind) = positional_error {
            return Err(XtablesRestoreParseError::at_line(line_number, kind));
        }
    }
    validate_command_order(context.action, command_stage, kind, line_number)?;

    let chain = parts[1];
    validate_chain(chain, line_number)?;
    validate_chain_family(chain, context.family, line_number)?;
    let mut arguments = Vec::with_capacity(parts.len().saturating_sub(2));
    for token in &parts[2..] {
        validate_rule_token(token, line_number)?;
        arguments.push(XtablesRestoreToken((*token).into()));
    }
    validate_arguments(&arguments, context.family, line_number)?;

    Ok(XtablesRestoreCommand {
        kind,
        chain: chain.into(),
        arguments: arguments.into_boxed_slice(),
    })
}

fn is_positional_rule_number(token: &str) -> bool {
    token
        .split(':')
        .all(|part| !part.is_empty() && part.as_bytes().iter().all(u8::is_ascii_digit))
}

fn validate_command_table(
    table: XtablesRestoreTable,
    command: XtablesRestoreCommandKind,
    line_number: usize,
) -> Result<(), XtablesRestoreParseError> {
    if table == XtablesRestoreTable::Mangle
        || !matches!(
            command,
            XtablesRestoreCommandKind::Flush | XtablesRestoreCommandKind::DeleteChain
        )
    {
        Ok(())
    } else {
        Err(XtablesRestoreParseError::at_line(
            line_number,
            XtablesRestoreParseErrorKind::CommandTableMismatch { table, command },
        ))
    }
}

fn validate_action(
    action: XtablesRestoreAction,
    command: XtablesRestoreCommandKind,
    line_number: usize,
) -> Result<(), XtablesRestoreParseError> {
    let matches = match action {
        XtablesRestoreAction::Apply => matches!(
            command,
            XtablesRestoreCommandKind::Append | XtablesRestoreCommandKind::Insert
        ),
        XtablesRestoreAction::Replace => matches!(
            command,
            XtablesRestoreCommandKind::Flush | XtablesRestoreCommandKind::Append
        ),
        XtablesRestoreAction::Cleanup => matches!(
            command,
            XtablesRestoreCommandKind::Delete
                | XtablesRestoreCommandKind::Flush
                | XtablesRestoreCommandKind::DeleteChain
        ),
    };
    if matches {
        Ok(())
    } else {
        Err(XtablesRestoreParseError::at_line(
            line_number,
            XtablesRestoreParseErrorKind::ActionMismatch { action, command },
        ))
    }
}

fn validate_command_arity(
    command: XtablesRestoreCommandKind,
    parts: &[&str],
    line_number: usize,
) -> Result<(), XtablesRestoreParseError> {
    let valid = match command {
        XtablesRestoreCommandKind::Append
        | XtablesRestoreCommandKind::Insert
        | XtablesRestoreCommandKind::Delete => parts.len() >= 3,
        XtablesRestoreCommandKind::Flush | XtablesRestoreCommandKind::DeleteChain => {
            parts.len() == 2
        }
    };
    if valid {
        Ok(())
    } else {
        Err(XtablesRestoreParseError::at_line(
            line_number,
            XtablesRestoreParseErrorKind::InvalidCommandArity { command },
        ))
    }
}

fn validate_command_order(
    action: XtablesRestoreAction,
    stage: CommandStage,
    command: XtablesRestoreCommandKind,
    line_number: usize,
) -> Result<(), XtablesRestoreParseError> {
    let valid = match action {
        XtablesRestoreAction::Apply => true,
        XtablesRestoreAction::Replace => match command {
            XtablesRestoreCommandKind::Flush => {
                matches!(stage, CommandStage::Initial | CommandStage::Flushing)
            }
            XtablesRestoreCommandKind::Append => {
                matches!(stage, CommandStage::Flushing | CommandStage::Populating)
            }
            XtablesRestoreCommandKind::Insert
            | XtablesRestoreCommandKind::Delete
            | XtablesRestoreCommandKind::DeleteChain => false,
        },
        XtablesRestoreAction::Cleanup => match command {
            XtablesRestoreCommandKind::Delete => stage == CommandStage::Initial,
            XtablesRestoreCommandKind::Flush => {
                matches!(stage, CommandStage::Initial | CommandStage::Flushing)
            }
            XtablesRestoreCommandKind::DeleteChain => {
                matches!(stage, CommandStage::Flushing | CommandStage::DeletingChains)
            }
            XtablesRestoreCommandKind::Append | XtablesRestoreCommandKind::Insert => false,
        },
    };
    if valid {
        Ok(())
    } else {
        Err(XtablesRestoreParseError::at_line(
            line_number,
            match action {
                XtablesRestoreAction::Replace => {
                    XtablesRestoreParseErrorKind::ReplaceOrdering { command }
                }
                XtablesRestoreAction::Cleanup => {
                    XtablesRestoreParseErrorKind::CleanupOrdering { command }
                }
                XtablesRestoreAction::Apply => unreachable!("apply ordering is unrestricted"),
            },
        ))
    }
}

const fn command_stage_after(
    action: XtablesRestoreAction,
    stage: CommandStage,
    command: XtablesRestoreCommandKind,
) -> CommandStage {
    match (action, command) {
        (XtablesRestoreAction::Replace, XtablesRestoreCommandKind::Flush)
        | (XtablesRestoreAction::Cleanup, XtablesRestoreCommandKind::Flush) => {
            CommandStage::Flushing
        }
        (XtablesRestoreAction::Replace, XtablesRestoreCommandKind::Append) => {
            CommandStage::Populating
        }
        (XtablesRestoreAction::Cleanup, XtablesRestoreCommandKind::DeleteChain) => {
            CommandStage::DeletingChains
        }
        _ => stage,
    }
}

fn validate_chain(chain: &str, line_number: usize) -> Result<(), XtablesRestoreParseError> {
    if chain.is_empty()
        || !chain.as_bytes()[0].is_ascii_uppercase()
        || !chain
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
    {
        return Err(XtablesRestoreParseError::at_line(
            line_number,
            XtablesRestoreParseErrorKind::InvalidChainName,
        ));
    }
    ensure_line_limit(
        line_number,
        XtablesRestoreLimit::ChainBytes,
        MAX_XTABLES_RESTORE_CHAIN_BYTES,
        chain.len(),
    )
}

fn validate_rule_token(token: &str, line_number: usize) -> Result<(), XtablesRestoreParseError> {
    ensure_line_limit(
        line_number,
        XtablesRestoreLimit::TokenBytes,
        MAX_XTABLES_RESTORE_TOKEN_BYTES,
        token.len(),
    )?;
    if token.is_empty()
        || !token.as_bytes().iter().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(*byte, b'_' | b'-' | b'+' | b'.' | b',' | b':' | b'/' | b'=')
        })
    {
        return Err(XtablesRestoreParseError::at_line(
            line_number,
            XtablesRestoreParseErrorKind::InvalidToken,
        ));
    }
    Ok(())
}

fn validate_arguments(
    arguments: &[XtablesRestoreToken],
    expected: XtablesRestoreFamily,
    line_number: usize,
) -> Result<(), XtablesRestoreParseError> {
    let mut index = 0;
    while index < arguments.len() {
        let option = arguments[index].as_str();
        match option {
            "-d" | "--to-destination" => {
                let value = required_option_value(arguments, index, line_number)?;
                validate_address_family(value, expected, line_number)?;
                index += 2;
            }
            "-p" => {
                let protocol = required_option_value(arguments, index, line_number)?;
                if !matches!(protocol, "tcp" | "udp" | "icmp" | "ipv6-icmp") {
                    return Err(XtablesRestoreParseError::at_line(
                        line_number,
                        XtablesRestoreParseErrorKind::UnsupportedProtocol,
                    ));
                }
                if (protocol == "icmp" && expected != XtablesRestoreFamily::Ipv4)
                    || (protocol == "ipv6-icmp" && expected != XtablesRestoreFamily::Ipv6)
                {
                    return Err(family_mismatch(expected, line_number));
                }
                index += 2;
            }
            "-j" => {
                let target = required_option_value(arguments, index, line_number)?;
                validate_jump_target(target, line_number)?;
                validate_chain_family(target, expected, line_number)?;
                index += 2;
            }
            "-m" | "--uid-owner" | "--gid-owner" | "--mark" | "--set-xmark" | "--on-port"
            | "--tproxy-mark" | "-i" | "-o" | "--ctdir" | "--dport" => {
                let _ = required_option_value(arguments, index, line_number)?;
                index += 2;
            }
            "--tcp-flags" => {
                let _ = required_option_value(arguments, index, line_number)?;
                let _ = required_option_value(arguments, index + 1, line_number)?;
                index += 3;
            }
            "--transparent" | "--clamp-mss-to-pmtu" => {
                index += 1;
            }
            _ => {
                return Err(XtablesRestoreParseError::at_line(
                    line_number,
                    XtablesRestoreParseErrorKind::UnsupportedRuleOption,
                ));
            }
        }
    }
    Ok(())
}

fn required_option_value(
    arguments: &[XtablesRestoreToken],
    index: usize,
    line_number: usize,
) -> Result<&str, XtablesRestoreParseError> {
    arguments
        .get(index + 1)
        .map(XtablesRestoreToken::as_str)
        .filter(|value| !value.starts_with('-'))
        .ok_or_else(|| {
            XtablesRestoreParseError::at_line(
                line_number,
                XtablesRestoreParseErrorKind::MissingOptionValue,
            )
        })
}

fn validate_jump_target(target: &str, line_number: usize) -> Result<(), XtablesRestoreParseError> {
    if target.is_empty()
        || !target.as_bytes()[0].is_ascii_uppercase()
        || !target
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
    {
        return Err(XtablesRestoreParseError::at_line(
            line_number,
            XtablesRestoreParseErrorKind::InvalidJumpTarget,
        ));
    }
    ensure_line_limit(
        line_number,
        XtablesRestoreLimit::ChainBytes,
        MAX_XTABLES_RESTORE_CHAIN_BYTES,
        target.len(),
    )
}

fn validate_address_family(
    token: &str,
    expected: XtablesRestoreFamily,
    line_number: usize,
) -> Result<(), XtablesRestoreParseError> {
    let (address, prefix) = match token.split_once('/') {
        Some((address, prefix)) if !prefix.contains('/') => (address, Some(prefix)),
        Some(_) => return Err(invalid_address(line_number)),
        None => (token, None),
    };
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| invalid_address(line_number))?;
    let family = match address {
        IpAddr::V4(_) => XtablesRestoreFamily::Ipv4,
        IpAddr::V6(_) => XtablesRestoreFamily::Ipv6,
    };
    if family != expected {
        return Err(family_mismatch(expected, line_number));
    }
    if let Some(prefix) = prefix {
        let width = match family {
            XtablesRestoreFamily::Ipv4 => 32,
            XtablesRestoreFamily::Ipv6 => 128,
        };
        if prefix.is_empty() || !prefix.as_bytes().iter().all(u8::is_ascii_digit) {
            return Err(invalid_address(line_number));
        }
        let parsed = prefix
            .parse::<u8>()
            .map_err(|_| invalid_address(line_number))?;
        if parsed > width || (prefix.len() > 1 && prefix.starts_with('0')) {
            return Err(invalid_address(line_number));
        }
    }
    Ok(())
}

fn validate_chain_family(
    chain: &str,
    expected: XtablesRestoreFamily,
    line_number: usize,
) -> Result<(), XtablesRestoreParseError> {
    match flux_chain_family(chain) {
        Some(actual) if actual != expected => {
            return Err(family_mismatch(expected, line_number));
        }
        None if has_reserved_flux_chain_prefix(chain) => {
            return Err(XtablesRestoreParseError::at_line(
                line_number,
                XtablesRestoreParseErrorKind::InvalidChainName,
            ));
        }
        Some(_) | None => {}
    }
    Ok(())
}

fn has_reserved_flux_chain_prefix(chain: &str) -> bool {
    [
        "PROXY_PREROUTING",
        "PROXY_OUTPUT",
        "BYPASS_IP",
        "APP_CHAIN",
        "ACTION_PROXY_PRE",
        "ACTION_PROXY_OUT",
        "ACTION_BYPASS",
        "DIVERT",
        "BYP_Z",
        "FLX",
    ]
    .into_iter()
    .any(|prefix| chain.starts_with(prefix))
}

fn flux_chain_family(chain: &str) -> Option<XtablesRestoreFamily> {
    if let Some(family) = capture_stable_chain_family(chain) {
        return Some(family);
    }
    if let Some(family) = capture_generation_chain_family(chain) {
        return Some(family);
    }

    const BASES: [&str; 8] = [
        "PROXY_PREROUTING",
        "PROXY_OUTPUT",
        "BYPASS_IP",
        "APP_CHAIN",
        "ACTION_PROXY_PRE",
        "ACTION_PROXY_OUT",
        "ACTION_BYPASS",
        "DIVERT",
    ];
    for base in BASES {
        if chain == base {
            return Some(XtablesRestoreFamily::Ipv4);
        }
        if chain.strip_suffix('6') == Some(base) {
            return Some(XtablesRestoreFamily::Ipv6);
        }
    }
    if let Some(zone) = chain.strip_prefix("BYP_Z") {
        for index in 0..16 {
            if zone == index.to_string() {
                return Some(XtablesRestoreFamily::Ipv4);
            }
            if zone == format!("{index}6") {
                return Some(XtablesRestoreFamily::Ipv6);
            }
        }
    }
    None
}

fn capture_stable_chain_family(chain: &str) -> Option<XtablesRestoreFamily> {
    match chain {
        "FLX4SP" | "FLX4SO" => Some(XtablesRestoreFamily::Ipv4),
        "FLX6SP" | "FLX6SO" => Some(XtablesRestoreFamily::Ipv6),
        _ => None,
    }
}

fn capture_generation_chain_family(chain: &str) -> Option<XtablesRestoreFamily> {
    let suffix = chain.strip_prefix("FLX")?;
    let bytes = suffix.as_bytes();
    if bytes.len() != 12 || !matches!(bytes[1], b'A' | b'C' | b'F' | b'O' | b'P') {
        return None;
    }
    let family = match bytes[0] {
        b'4' => XtablesRestoreFamily::Ipv4,
        b'6' => XtablesRestoreFamily::Ipv6,
        _ => return None,
    };
    let generation = &suffix[2..];
    if generation.len() != 10
        || !generation.as_bytes().iter().all(u8::is_ascii_digit)
        || generation
            .parse::<u32>()
            .ok()
            .filter(|value| *value != 0)
            .is_none()
    {
        return None;
    }
    Some(family)
}

const fn family_mismatch(
    expected: XtablesRestoreFamily,
    line_number: usize,
) -> XtablesRestoreParseError {
    XtablesRestoreParseError::at_line(
        line_number,
        XtablesRestoreParseErrorKind::FamilyMismatch { expected },
    )
}

const fn invalid_address(line_number: usize) -> XtablesRestoreParseError {
    XtablesRestoreParseError::at_line(line_number, XtablesRestoreParseErrorKind::InvalidAddress)
}

fn ensure_limit(
    resource: XtablesRestoreLimit,
    maximum: usize,
    actual: usize,
) -> Result<(), XtablesRestoreParseError> {
    if actual <= maximum {
        Ok(())
    } else {
        Err(XtablesRestoreParseError::global(
            XtablesRestoreParseErrorKind::LimitExceeded {
                resource,
                maximum,
                actual,
            },
        ))
    }
}

fn ensure_line_limit(
    line_number: usize,
    resource: XtablesRestoreLimit,
    maximum: usize,
    actual: usize,
) -> Result<(), XtablesRestoreParseError> {
    if actual <= maximum {
        Ok(())
    } else {
        Err(XtablesRestoreParseError::at_line(
            line_number,
            XtablesRestoreParseErrorKind::LimitExceeded {
                resource,
                maximum,
                actual,
            },
        ))
    }
}

fn render_transactions(transactions: &[XtablesRestoreTransaction], capacity: usize) -> Box<[u8]> {
    let mut output = Vec::with_capacity(capacity);
    for transaction in transactions {
        output.push(b'*');
        output.extend_from_slice(transaction.table.as_str().as_bytes());
        output.push(b'\n');
        for entry in &transaction.entries {
            match entry {
                XtablesRestoreEntry::ChainDeclaration(declaration) => {
                    output.push(b':');
                    output.extend_from_slice(declaration.chain.as_bytes());
                    output.extend_from_slice(b" - [0:0]\n");
                }
                XtablesRestoreEntry::Command(command) => {
                    output.extend_from_slice(command.kind.as_str().as_bytes());
                    output.push(b' ');
                    output.extend_from_slice(command.chain.as_bytes());
                    for argument in &command.arguments {
                        output.push(b' ');
                        output.extend_from_slice(argument.as_str().as_bytes());
                    }
                    output.push(b'\n');
                }
            }
        }
        output.extend_from_slice(b"COMMIT\n");
    }
    output.into_boxed_slice()
}

fn digest_restore(context: XtablesRestoreContext, canonical: &[u8]) -> XtablesRestoreDigest {
    let mut digest = Sha256::new();
    digest.update(XTABLES_RESTORE_DIGEST_DOMAIN);
    digest.update(XTABLES_RESTORE_SCHEMA_VERSION.to_be_bytes());
    digest.update([match context.action {
        XtablesRestoreAction::Apply => 1,
        XtablesRestoreAction::Cleanup => 2,
        XtablesRestoreAction::Replace => 3,
    }]);
    digest.update([match context.family {
        XtablesRestoreFamily::Ipv4 => 4,
        XtablesRestoreFamily::Ipv6 => 6,
    }]);
    digest.update(
        u64::try_from(canonical.len())
            .expect("restore byte limit fits u64")
            .to_be_bytes(),
    );
    digest.update(canonical);
    XtablesRestoreDigest(digest.finalize().into())
}
