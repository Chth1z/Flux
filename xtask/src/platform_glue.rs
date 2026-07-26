use super::{FORBIDDEN_PLATFORM_GLUE_EXECUTABLES, FORBIDDEN_PLATFORM_GLUE_FRAGMENTS};

#[derive(Clone, Debug, Eq, PartialEq)]
struct ShellWord {
    literal: String,
    dynamic: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Operator {
    Boundary,
    LeftParen,
    RightParen,
    LeftBrace,
    RightBrace,
    Redirection,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Token {
    Word(ShellWord),
    Operator(Operator),
}

#[derive(Clone, Debug)]
struct CommandNode {
    executable: ShellWord,
    arguments: Vec<ShellWord>,
}

pub(super) fn validate_structure(relative: &str, source: &str) -> Result<(), String> {
    let tokens = lex(relative, source)?;
    let commands = parse_commands(relative, &tokens)?;
    validate_commands(relative, &commands)?;
    validate_delegation(relative, &commands)
}

fn lex(relative: &str, source: &str) -> Result<Vec<Token>, String> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b' ' | b'\t' | b'\r' => index += 1,
            b'\n' | b';' | b'|' | b'&' => {
                index += usize::from(index + 1 < bytes.len() && bytes[index + 1] == bytes[index]);
                index += 1;
                tokens.push(Token::Operator(Operator::Boundary));
            }
            b'(' => {
                tokens.push(Token::Operator(Operator::LeftParen));
                index += 1;
            }
            b')' => {
                tokens.push(Token::Operator(Operator::RightParen));
                index += 1;
            }
            b'{' => {
                tokens.push(Token::Operator(Operator::LeftBrace));
                index += 1;
            }
            b'}' => {
                tokens.push(Token::Operator(Operator::RightBrace));
                index += 1;
            }
            b'<' | b'>' => {
                let marker = bytes[index];
                index += 1;
                if index < bytes.len() && bytes[index] == marker {
                    index += 1;
                }
                tokens.push(Token::Operator(Operator::Redirection));
            }
            b'#' => {
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
            }
            b'\\' if bytes.get(index + 1) == Some(&b'\n') => {
                index += 2;
            }
            b'\\'
                if bytes.get(index + 1) == Some(&b'\r') && bytes.get(index + 2) == Some(&b'\n') =>
            {
                index += 3;
            }
            _ => tokens.push(Token::Word(read_word(relative, bytes, &mut index)?)),
        }
    }
    Ok(tokens)
}

fn read_word(relative: &str, bytes: &[u8], index: &mut usize) -> Result<ShellWord, String> {
    let start = *index;
    let mut literal = String::new();
    let mut dynamic = false;
    while *index < bytes.len() {
        match bytes[*index] {
            b' ' | b'\t' | b'\r' | b'\n' | b';' | b'|' | b'&' | b'(' | b')' | b'{' | b'}'
            | b'<' | b'>' => break,
            b'\\' => {
                *index += 1;
                if *index >= bytes.len() {
                    return Err(format!(
                        "Rust-only platform glue {relative} ends with an incomplete escape"
                    ));
                }
                if bytes[*index] == b'\r' && *index + 1 < bytes.len() && bytes[*index + 1] == b'\n'
                {
                    *index += 2;
                } else if bytes[*index] == b'\n' {
                    *index += 1;
                } else {
                    literal.push(char::from(bytes[*index]));
                    *index += 1;
                }
            }
            b'\'' => read_single_quoted(relative, bytes, index, &mut literal)?,
            b'"' => read_double_quoted(relative, bytes, index, &mut literal, &mut dynamic)?,
            b'$' => read_dollar(relative, bytes, index, &mut literal, &mut dynamic)?,
            b'`' => {
                return Err(format!(
                    "Rust-only platform glue {relative} contains forbidden dynamic command construction using backticks"
                ));
            }
            byte => {
                literal.push(char::from(byte));
                *index += 1;
            }
        }
    }
    if literal.is_empty() && !dynamic {
        return Err(format!(
            "Rust-only platform glue {relative} contains an empty shell word at byte {start}"
        ));
    }
    Ok(ShellWord { literal, dynamic })
}

fn read_single_quoted(
    relative: &str,
    bytes: &[u8],
    index: &mut usize,
    literal: &mut String,
) -> Result<(), String> {
    *index += 1;
    let start = *index;
    while *index < bytes.len() && bytes[*index] != b'\'' {
        *index += 1;
    }
    if *index == bytes.len() {
        return Err(format!(
            "Rust-only platform glue {relative} contains an unterminated single quote"
        ));
    }
    literal.push_str(std::str::from_utf8(&bytes[start..*index]).expect("ASCII source"));
    *index += 1;
    Ok(())
}

fn read_double_quoted(
    relative: &str,
    bytes: &[u8],
    index: &mut usize,
    literal: &mut String,
    dynamic: &mut bool,
) -> Result<(), String> {
    *index += 1;
    while *index < bytes.len() && bytes[*index] != b'"' {
        match bytes[*index] {
            b'\\' => {
                *index += 1;
                if *index >= bytes.len() {
                    break;
                }
                if bytes[*index] == b'\n' {
                    *index += 1;
                } else {
                    literal.push(char::from(bytes[*index]));
                    *index += 1;
                }
            }
            b'$' => read_dollar(relative, bytes, index, literal, dynamic)?,
            b'`' => {
                return Err(format!(
                    "Rust-only platform glue {relative} contains forbidden dynamic command construction using backticks"
                ));
            }
            byte => {
                literal.push(char::from(byte));
                *index += 1;
            }
        }
    }
    if *index == bytes.len() {
        return Err(format!(
            "Rust-only platform glue {relative} contains an unterminated double quote"
        ));
    }
    *index += 1;
    Ok(())
}

fn read_dollar(
    relative: &str,
    bytes: &[u8],
    index: &mut usize,
    literal: &mut String,
    dynamic: &mut bool,
) -> Result<(), String> {
    *dynamic = true;
    *index += 1;
    if *index >= bytes.len() {
        return Ok(());
    }
    if bytes[*index] == b'(' {
        if *index + 1 < bytes.len() && bytes[*index + 1] == b'(' {
            skip_arithmetic(relative, bytes, index)?;
            return Ok(());
        }
        return Err(format!(
            "Rust-only platform glue {relative} contains forbidden dynamic command construction using command substitution"
        ));
    }
    if bytes[*index] == b'{' {
        *index += 1;
        while *index < bytes.len() && bytes[*index] != b'}' {
            *index += 1;
        }
        if *index == bytes.len() {
            return Err(format!(
                "Rust-only platform glue {relative} contains an unterminated parameter expansion"
            ));
        }
        *index += 1;
        return Ok(());
    }
    if bytes[*index].is_ascii_alphabetic() || bytes[*index] == b'_' {
        while *index < bytes.len()
            && (bytes[*index].is_ascii_alphanumeric() || bytes[*index] == b'_')
        {
            *index += 1;
        }
    } else {
        *index += 1;
    }
    let _ = literal;
    Ok(())
}

fn skip_arithmetic(relative: &str, bytes: &[u8], index: &mut usize) -> Result<(), String> {
    *index += 2;
    let mut depth = 1usize;
    while *index + 1 < bytes.len() {
        if bytes[*index] == b'(' {
            depth += 1;
            *index += 1;
        } else if bytes[*index] == b')' && bytes[*index + 1] == b')' {
            depth -= 1;
            *index += 2;
            if depth == 0 {
                return Ok(());
            }
        } else {
            *index += 1;
        }
    }
    Err(format!(
        "Rust-only platform glue {relative} contains an unterminated arithmetic expansion"
    ))
}

fn parse_commands(relative: &str, tokens: &[Token]) -> Result<Vec<CommandNode>, String> {
    let mut commands = Vec::new();
    let mut index = 0;
    let mut expecting_command = true;
    while index < tokens.len() {
        match &tokens[index] {
            Token::Operator(Operator::Boundary | Operator::LeftBrace | Operator::LeftParen) => {
                expecting_command = true;
                index += 1;
            }
            Token::Operator(Operator::RightBrace | Operator::RightParen) => {
                index += 1;
            }
            Token::Operator(Operator::Redirection) => {
                index += 1;
                if matches!(tokens.get(index), Some(Token::Word(_))) {
                    index += 1;
                }
            }
            Token::Word(word) if expecting_command && is_assignment(&word.literal) => index += 1,
            Token::Word(word) if expecting_command && is_control_keyword(&word.literal) => {
                expecting_command = keyword_expects_command(&word.literal);
                index += 1;
            }
            Token::Word(word) if expecting_command => {
                if is_function_declaration(tokens, index) {
                    index += 4;
                    expecting_command = true;
                    continue;
                }
                let mut command = CommandNode {
                    executable: word.clone(),
                    arguments: Vec::new(),
                };
                index += 1;
                while index < tokens.len() {
                    match &tokens[index] {
                        Token::Word(argument) => {
                            command.arguments.push(argument.clone());
                            index += 1;
                        }
                        Token::Operator(Operator::Redirection) => {
                            index += 1;
                            if matches!(tokens.get(index), Some(Token::Word(_))) {
                                index += 1;
                            }
                        }
                        _ => break,
                    }
                }
                commands.push(command);
                expecting_command = false;
            }
            Token::Word(_) => index += 1,
        }
    }
    if commands.is_empty() {
        return Err(format!(
            "Rust-only platform glue {relative} contains no executable commands"
        ));
    }
    Ok(commands)
}

fn is_function_declaration(tokens: &[Token], index: usize) -> bool {
    matches!(tokens.get(index), Some(Token::Word(word)) if is_identifier(&word.literal) && !word.dynamic)
        && matches!(
            tokens.get(index + 1),
            Some(Token::Operator(Operator::LeftParen))
        )
        && matches!(
            tokens.get(index + 2),
            Some(Token::Operator(Operator::RightParen))
        )
        && matches!(
            tokens.get(index + 3),
            Some(Token::Operator(Operator::LeftBrace))
        )
}

fn is_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(first) if first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn is_assignment(value: &str) -> bool {
    value
        .split_once('=')
        .is_some_and(|(name, _)| is_identifier(name))
}

fn is_control_keyword(value: &str) -> bool {
    matches!(
        value,
        "if" | "then"
            | "else"
            | "elif"
            | "fi"
            | "while"
            | "until"
            | "do"
            | "done"
            | "for"
            | "in"
            | "case"
            | "esac"
            | "!"
    )
}

fn keyword_expects_command(value: &str) -> bool {
    matches!(
        value,
        "if" | "then" | "else" | "elif" | "while" | "until" | "do" | "!"
    )
}

fn validate_commands(relative: &str, commands: &[CommandNode]) -> Result<(), String> {
    for command in commands {
        let effective = effective_command(relative, command)?;
        let executable = basename(&effective.executable.literal).to_ascii_lowercase();
        if let Some((category, _)) = FORBIDDEN_PLATFORM_GLUE_EXECUTABLES
            .iter()
            .find(|(_, forbidden)| executable == *forbidden)
        {
            return Err(format!(
                "Rust-only platform glue {relative} invokes forbidden {category} executable '{executable}'"
            ));
        }
        if matches!(
            executable.as_str(),
            "sh" | "ash" | "bash" | "dash" | "busybox" | "toybox" | "env" | "xargs" | "command"
        ) {
            return Err(format!(
                "Rust-only platform glue {relative} contains forbidden dynamic command construction through '{executable}'"
            ));
        }
        if executable == "trap" {
            let action = effective.arguments.first().ok_or_else(|| {
                format!("Rust-only platform glue {relative} contains a trap without an action")
            })?;
            if action.dynamic || (action.literal != "-" && !is_identifier(&action.literal)) {
                return Err(format!(
                    "Rust-only platform glue {relative} contains forbidden dynamic command construction in a trap action"
                ));
            }
        }
        for word in std::iter::once(&effective.executable).chain(effective.arguments.iter()) {
            let normalized = word.literal.to_ascii_lowercase();
            if let Some((category, fragment)) = FORBIDDEN_PLATFORM_GLUE_FRAGMENTS
                .iter()
                .find(|(_, forbidden)| normalized.contains(*forbidden))
            {
                return Err(format!(
                    "Rust-only platform glue {relative} contains forbidden {category} marker '{fragment}' in shell syntax"
                ));
            }
        }
    }
    Ok(())
}

fn effective_command(relative: &str, command: &CommandNode) -> Result<CommandNode, String> {
    if command.executable.dynamic {
        return Err(format!(
            "Rust-only platform glue {relative} contains forbidden dynamic command construction in executable position"
        ));
    }
    if command.executable.literal != "exec" {
        return Ok(command.clone());
    }
    let (executable, arguments) = command.arguments.split_first().ok_or_else(|| {
        format!("Rust-only platform glue {relative} contains exec without a direct command")
    })?;
    if executable.dynamic {
        return Err(format!(
            "Rust-only platform glue {relative} contains forbidden dynamic command construction after exec"
        ));
    }
    Ok(CommandNode {
        executable: executable.clone(),
        arguments: arguments.to_vec(),
    })
}

fn validate_delegation(relative: &str, commands: &[CommandNode]) -> Result<(), String> {
    match relative {
        "META-INF/com/google/android/update-binary" => {
            require_command(relative, commands, "install_module", &[])
        }
        "customize.sh" => {
            for required in ["bin/fluxd", "flux_service.sh", "uninstall.sh"] {
                let found = commands.iter().any(|command| {
                    matches!(basename(&command.executable.literal), "[" | "unzip")
                        && command.arguments.iter().any(|argument| {
                            !argument.dynamic && argument.literal.ends_with(required)
                                || argument.dynamic && argument.literal.ends_with(required)
                        })
                });
                if !found {
                    return Err(format!(
                        "Rust-only platform glue {relative} is missing required placement check '{required}'"
                    ));
                }
            }
            Ok(())
        }
        "flux_service.sh" => {
            require_command(relative, commands, "/data/adb/flux/bin/fluxd", &["daemon"])
        }
        "uninstall.sh" => {
            require_command(relative, commands, "/data/adb/flux/bin/fluxd", &["ping"])?;
            require_command(relative, commands, "/data/adb/flux/bin/fluxd", &["stop"])?;
            require_command(
                relative,
                commands,
                "/data/adb/flux/bin/fluxd",
                &["cleanup", "--offline"],
            )
        }
        _ => Err(format!(
            "unreviewed Rust-only platform glue path {relative}"
        )),
    }
}

fn require_command(
    relative: &str,
    commands: &[CommandNode],
    executable: &str,
    arguments: &[&str],
) -> Result<(), String> {
    let found = commands.iter().any(|command| {
        effective_command(relative, command).is_ok_and(|command| {
            command.executable.literal == executable
                && command.arguments.len() >= arguments.len()
                && command
                    .arguments
                    .iter()
                    .zip(arguments)
                    .all(|(actual, expected)| !actual.dynamic && actual.literal == *expected)
        })
    });
    if found {
        Ok(())
    } else {
        Err(format!(
            "Rust-only platform glue {relative} is missing required direct delegation command '{executable} {}'",
            arguments.join(" ")
        ))
    }
}

fn basename(value: &str) -> &str {
    value.rsplit('/').next().unwrap_or(value)
}
