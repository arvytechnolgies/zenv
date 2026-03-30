use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
    Unknown,
}

impl Shell {
    /// Detect shell from $SHELL env var.
    pub fn detect() -> Self {
        match std::env::var("SHELL") {
            Ok(s) => {
                if s.ends_with("/zsh") || s.ends_with("/zsh-") {
                    Shell::Zsh
                } else if s.ends_with("/bash") {
                    Shell::Bash
                } else if s.ends_with("/fish") {
                    Shell::Fish
                } else {
                    Shell::Unknown
                }
            }
            Err(_) => Shell::Unknown,
        }
    }

    pub fn from_str_opt(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "bash" => Shell::Bash,
            "zsh" => Shell::Zsh,
            "fish" => Shell::Fish,
            _ => Shell::Unknown,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Shell::Bash => "bash",
            Shell::Zsh => "zsh",
            Shell::Fish => "fish",
            Shell::Unknown => "unknown",
        }
    }
}

/// Returns the one-liner to add to the shell RC file.
pub fn install_snippet(shell: Shell) -> String {
    match shell {
        Shell::Fish => r#"# zenv auto-load
if type -q zenv
    zenv shell hook --shell fish | source
end"#
            .to_string(),
        Shell::Zsh => r#"# zenv auto-load
eval "$(zenv shell hook --shell zsh)""#
            .to_string(),
        Shell::Bash => r#"# zenv auto-load
eval "$(zenv shell hook --shell bash)""#
            .to_string(),
        Shell::Unknown => r#"# zenv auto-load (adjust for your shell)
eval "$(zenv shell hook)""#
            .to_string(),
    }
}

/// Format export statements for the given shell.
pub fn format_exports(env: &HashMap<String, String>, shell: Shell) -> String {
    let mut lines: Vec<String> = env
        .iter()
        .map(|(k, v)| format_single_export(k, v, shell))
        .collect();
    lines.sort();
    lines.join("\n")
}

fn format_single_export(key: &str, value: &str, shell: Shell) -> String {
    let escaped = escape_single_quotes(value);
    match shell {
        Shell::Fish => format!("set -gx {} '{}'", key, escaped),
        _ => format!("export {}='{}'", key, escaped),
    }
}

/// Escape single quotes for shell: replace ' with '\''
fn escape_single_quotes(s: &str) -> String {
    s.replace('\'', "'\\''")
}

/// Generate the full hook script that gets eval'd.
/// On directory change, checks for .zenv.toml and loads secrets.
pub fn hook_script(shell: Shell) -> String {
    match shell {
        Shell::Zsh => r#"__zenv_load() {
    local root
    root=$(git rev-parse --show-toplevel 2>/dev/null)
    if [ -n "$root" ] && [ -f "$root/.zenv.toml" ]; then
        eval "$(zenv shell export --shell zsh)"
        export ZENV_ACTIVE=1
        export ZENV_PROJECT="$root"
    elif [ -n "$ZENV_ACTIVE" ]; then
        unset ZENV_ACTIVE
        unset ZENV_PROJECT
    fi
}
autoload -Uz add-zsh-hook
add-zsh-hook chpwd __zenv_load
__zenv_load"#
            .to_string(),

        Shell::Bash => r#"__zenv_cd_hook() {
    local root
    root=$(git rev-parse --show-toplevel 2>/dev/null)
    if [ -n "$root" ] && [ -f "$root/.zenv.toml" ]; then
        eval "$(zenv shell export --shell bash)"
        export ZENV_ACTIVE=1
        export ZENV_PROJECT="$root"
    elif [ -n "$ZENV_ACTIVE" ]; then
        unset ZENV_ACTIVE
        unset ZENV_PROJECT
    fi
}
if [[ ! "$PROMPT_COMMAND" =~ __zenv_cd_hook ]]; then
    PROMPT_COMMAND="__zenv_cd_hook;${PROMPT_COMMAND:-}"
fi
__zenv_cd_hook"#
            .to_string(),

        Shell::Fish => r#"function __zenv_load --on-variable PWD
    set -l root (git rev-parse --show-toplevel 2>/dev/null)
    if test -n "$root"; and test -f "$root/.zenv.toml"
        eval (zenv shell export --shell fish)
        set -gx ZENV_ACTIVE 1
        set -gx ZENV_PROJECT $root
    else if set -q ZENV_ACTIVE
        set -e ZENV_ACTIVE
        set -e ZENV_PROJECT
    end
end
__zenv_load"#
            .to_string(),

        Shell::Unknown => r#"# zenv: unknown shell — add directory-change hook manually
# eval "$(zenv shell export)" in your shell's chpwd equivalent"#
            .to_string(),
    }
}
