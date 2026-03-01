#!/bin/bash

# ANSI color codes for status indicators using $'...' syntax for proper interpretation
green_color=$'\033[38;5;46m'
orange_color=$'\033[38;5;214m'
red_color=$'\033[38;5;196m'
reset_color=$'\033[0m'

# Read JSON input from stdin
input=$(cat)

# Get current working directory from JSON input
cwd=$(echo "$input" | jq -r ".workspace.current_dir")
cd "$cwd" 2>/dev/null || cd "$HOME"

# Extract Claude model from JSON input
model_name=$(echo "$input" | jq -r ".model.id // .model // empty" 2>/dev/null)

# Fallback to settings.json if not in input
if [ -z "$model_name" ] || [ "$model_name" = "null" ]; then
    if [ -f "$HOME/.claude/settings.json" ]; then
        model_name=$(jq -r ".model // empty" "$HOME/.claude/settings.json" 2>/dev/null)
    fi
fi

# Format model name for display with proper ANSI colors
model_display=""
if [ -n "$model_name" ] && [ "$model_name" != "null" ]; then
    # Anthropic brand color (coral/orange): RGB(217, 119, 87)
    # Using ANSI 256-color approximation: color 209
    anthropic_color=$'\033[38;5;209m'
    reset_color=$'\033[0m'

    # Simplify model name if needed
    case "$model_name" in
        *"sonnet"*)
            model_display="${anthropic_color}sonnet${reset_color}"
            ;;
        *"opus"*)
            model_display="${anthropic_color}opus${reset_color}"
            ;;
        *"haiku"*)
            model_display="${anthropic_color}haiku${reset_color}"
            ;;
        *)
            model_display="${anthropic_color}${model_name}${reset_color}"
            ;;
    esac
fi

# Initialize output variables
git_info=""
env_info=""

# Git repository information
if git rev-parse --git-dir >/dev/null 2>&1; then
    # Get branch name or short commit hash
    branch=$(git branch --show-current 2>/dev/null)
    [ -z "$branch" ] && branch=$(git rev-parse --short HEAD 2>/dev/null)

    # Get remote repository name (org/repo)
    # Parse git@github.com:Vulnetix/vdb-manager.git or https://github.com/Vulnetix/vdb-manager.git
    remote=$(git remote get-url origin 2>/dev/null | sed -E 's|^.*github\.com[:/]||' | sed 's|\.git$||')

    # Build base git info
    git_info="$remote/$branch"

    # Check PR status using gh CLI
    pr_status="📝" # No PR exists for this branch
    if command -v gh >/dev/null 2>&1; then
        # Check if branch is protected (main/master)
        if [[ "$branch" == "main" ]] || [[ "$branch" == "master" ]]; then
            pr_status="${orange_color}[protected]${reset_color}"
        else
            # Check for PR from current branch
            pr_info=$(gh pr list --head "$branch" --json number,state 2>/dev/null | jq -r '.[0] | "\(.number),\(.state)"' 2>/dev/null)

            if [ -n "$pr_info" ] && [ "$pr_info" != "null,null" ] && [ "$pr_info" != "," ]; then
                pr_number=$(echo "$pr_info" | cut -d',' -f1)
                pr_state=$(echo "$pr_info" | cut -d',' -f2)

                case "$pr_state" in
                    OPEN)
                        pr_status="🔀#$pr_number"
                        ;;
                    MERGED)
                        pr_status="✅"
                        ;;
                    CLOSED)
                        pr_status="❌"
                        ;;
                esac
            fi
        fi
    fi

    # Add PR status to git info if present
    [ -n "$pr_status" ] && git_info="$git_info $pr_status"

    # Get upstream tracking info for drift indicators
    upstream=$(git rev-parse --abbrev-ref --symbolic-full-name @{u} 2>/dev/null)

    if [ -n "$upstream" ]; then
        # ahead = commits on remote not on local (we are behind)
        ahead=$(git rev-list --count HEAD...$upstream 2>/dev/null || echo "0")
        # behind = commits on local not on remote (we are ahead)
        behind=$(git rev-list --count $upstream...HEAD 2>/dev/null || echo "0")

        # Build drift indicator
        drift=""
        [ "$behind" -gt 0 ] && drift="↑$behind"
        [ "$ahead" -gt 0 ] && [ -n "$drift" ] && drift="$drift↓$ahead" || [ "$ahead" -gt 0 ] && drift="↓$ahead"

        # Add drift to git info if present
        [ -n "$drift" ] && git_info="$git_info $drift"
    fi

    # Get staged files count
    staged=$(git diff --cached --numstat 2>/dev/null | wc -l | tr -d ' ')

    # Add staged files indicator if present
    [ "$staged" -gt 0 ] && git_info="$git_info ●$staged"
fi

# Environment and tooling information (vdb-manager is a Node.js project)
if [ -f "package.json" ]; then
    # Node.js environment
    env_parts=()

    # Node.js version
    if command -v node >/dev/null 2>&1; then
        node_version=$(node --version 2>/dev/null | sed 's/v//')
        [ -n "$node_version" ] && env_parts+=("node:$node_version")
    fi

    # Yarn version (only if yarn is available)
    if command -v yarn >/dev/null 2>&1; then
        yarn_version=$(yarn --version 2>/dev/null)
        [ -n "$yarn_version" ] && env_parts+=("yarn:$yarn_version")
    fi

    # Join environment parts
    env_info=$(IFS=' '; echo "${env_parts[*]}")

    # Check for outdated packages
    if command -v yarn >/dev/null 2>&1 && [ -f "yarn.lock" ]; then
        outdated=$(yarn outdated --json 2>/dev/null | grep -c "table" | tr -d '\n' || echo "0")
        outdated=$(echo "$outdated" | tr -d ' ')
        [ -n "$outdated" ] && [ "$outdated" -gt 0 ] 2>/dev/null && env_info="$env_info [outdated:$outdated]"
    elif command -v npm >/dev/null 2>&1 && [ -f "package-lock.json" ]; then
        outdated=$(npm outdated --json 2>/dev/null | jq "length" 2>/dev/null || echo "0")
        [ "$outdated" -gt 0 ] && env_info="$env_info [outdated:$outdated]"
    fi
fi

# Claude API usage bars
credentials_file="$HOME/.claude/.credentials.json"
cache_file="/tmp/claude-usage-cache.json"
cache_ttl=60

if [ -f "$credentials_file" ] && command -v jq >/dev/null 2>&1; then
    token=$(jq -r '.claudeAiOauth.accessToken // empty' "$credentials_file" 2>/dev/null)

    if [ -n "$token" ]; then
        # Check cache freshness
        fetch_new=true
        if [ -f "$cache_file" ]; then
            cache_age=$(( $(date +%s) - $(stat -c%Y "$cache_file" 2>/dev/null || echo 0) ))
            [ "$cache_age" -lt "$cache_ttl" ] && fetch_new=false
        fi

        if $fetch_new; then
            api_response=$(curl -s --max-time 5 -H "Authorization: Bearer $token" -H "anthropic-beta: oauth-2025-04-20" -H "Content-Type: application/json" "https://api.anthropic.com/api/oauth/usage" 2>/dev/null)
            if [ -n "$api_response" ] && echo "$api_response" | jq -e '.five_hour' >/dev/null 2>&1; then
                echo "$api_response" > "$cache_file"
            fi
        fi

        if [ -f "$cache_file" ]; then
            usage_data=$(cat "$cache_file")

            # Function to build a bar
            build_bar() {
                local label="$1" utilization="$2" resets_at="$3"

                [ -z "$utilization" ] || [ "$utilization" = "null" ] && return

                # Round utilization to integer
                local pct=$(printf "%.0f" "$utilization" 2>/dev/null)
                [ -z "$pct" ] && return

                local filled=$(( pct * 10 / 100 ))
                [ "$filled" -gt 10 ] && filled=10
                [ "$filled" -lt 0 ] && filled=0
                local empty=$(( 10 - filled ))

                # Color by utilization
                local bar_color
                if [ "$pct" -ge 85 ]; then
                    bar_color="$red_color"
                elif [ "$pct" -ge 60 ]; then
                    bar_color="$orange_color"
                else
                    bar_color="$green_color"
                fi

                # Build bar string
                local bar_filled="" bar_empty=""
                for ((i=0; i<filled; i++)); do bar_filled+="█"; done
                for ((i=0; i<empty; i++)); do bar_empty+="░"; done

                # Format reset time
                local reset_str=""
                if [ -n "$resets_at" ] && [ "$resets_at" != "null" ]; then
                    local reset_epoch=$(date -d "$resets_at" +%s 2>/dev/null)
                    if [ -n "$reset_epoch" ]; then
                        local now_epoch=$(date +%s)
                        local delta=$(( reset_epoch - now_epoch ))
                        if [ "$delta" -gt 0 ]; then
                            if [ "$delta" -lt 86400 ]; then
                                local hours=$(( delta / 3600 ))
                                local mins=$(( (delta % 3600) / 60 ))
                                printf -v reset_str "~%dh %02dm" "$hours" "$mins"
                            else
                                reset_str="~$(date -d "$resets_at" '+%a %H:%M' 2>/dev/null)"
                            fi
                        fi
                    fi
                fi

                printf "%-7s %s%s%s%s %3d%% %-10s" "$label" "$bar_color" "$bar_filled" "$bar_empty" "$reset_color" "$pct" "$reset_str"
            }

            # Extract limits - try session (5h), model-specific (7d), and weekly (7d)
            bars=()

            session_util=$(echo "$usage_data" | jq -r '.five_hour.utilization // empty' 2>/dev/null)
            session_reset=$(echo "$usage_data" | jq -r '.five_hour.resets_at // empty' 2>/dev/null)
            if [ -n "$session_util" ] && [ "$session_util" != "null" ]; then
                bars+=("$(build_bar "Session" "$session_util" "$session_reset")")
            fi

            # Model-specific 7-day limit (check sonnet first as most common, then opus)
            for model_key in seven_day_sonnet seven_day_opus seven_day_haiku; do
                model_util=$(echo "$usage_data" | jq -r ".${model_key}.utilization // empty" 2>/dev/null)
                model_reset=$(echo "$usage_data" | jq -r ".${model_key}.resets_at // empty" 2>/dev/null)
                if [ -n "$model_util" ] && [ "$model_util" != "null" ]; then
                    model_label=$(echo "$model_key" | sed 's/seven_day_//' | sed 's/.*/\u&/')
                    bars+=("$(build_bar "$model_label" "$model_util" "$model_reset")")
                fi
            done

            weekly_util=$(echo "$usage_data" | jq -r '.seven_day.utilization // empty' 2>/dev/null)
            weekly_reset=$(echo "$usage_data" | jq -r '.seven_day.resets_at // empty' 2>/dev/null)
            if [ -n "$weekly_util" ] && [ "$weekly_util" != "null" ]; then
                bars+=("$(build_bar "Week" "$weekly_util" "$weekly_reset")")
            fi

            : # bars array populated above
        fi
    fi
fi

# Context window usage from current session
context_display=""
session_dir="$HOME/.claude/projects/-home-chris-GitHub-Vulnetix-saas"
if [ -d "$session_dir" ]; then
    latest_jsonl=$(ls -t "$session_dir"/*.jsonl 2>/dev/null | head -1)
    if [ -n "$latest_jsonl" ]; then
        # Get last assistant message's input tokens (= current context size)
        ctx_tokens=$(tail -20 "$latest_jsonl" 2>/dev/null | jq -s '[.[] | select(.message.usage) | .message.usage] | last | (.input_tokens + .cache_creation_input_tokens + .cache_read_input_tokens) // 0' 2>/dev/null)
        if [ -n "$ctx_tokens" ] && [ "$ctx_tokens" -gt 0 ] 2>/dev/null; then
            # Context window size by model (tokens)
            ctx_limit=200000
            case "$model_name" in
                *opus-4-6*|*opus-4-5*)   ctx_limit=200000 ;;
                *sonnet-4-5*)            ctx_limit=200000 ;;
                *haiku-4-5*)             ctx_limit=200000 ;;
                *opus-4-0*)              ctx_limit=200000 ;;
                *sonnet-4-0*)            ctx_limit=200000 ;;
                *opus-3-5*|*opus-3*)     ctx_limit=200000 ;;
                *sonnet-3-5*|*sonnet-3*) ctx_limit=200000 ;;
                *haiku-3-5*|*haiku-3*)   ctx_limit=200000 ;;
            esac
            ctx_pct=$(( ctx_tokens * 100 / ctx_limit ))
            [ "$ctx_pct" -gt 100 ] && ctx_pct=100
            ctx_k=$(( ctx_tokens / 1000 ))
            # Color
            if [ "$ctx_pct" -ge 85 ]; then
                ctx_color="$red_color"
            elif [ "$ctx_pct" -ge 60 ]; then
                ctx_color="$orange_color"
            else
                ctx_color="$green_color"
            fi
            ctx_limit_k=$(( ctx_limit / 1000 ))
            context_display="${ctx_color}${ctx_k}k${reset_color}/${ctx_limit_k}k ctx"
        fi
    fi
fi

# Build final status line
status_line=""

# Add model display
model_with_brackets=""
if [ -n "$model_display" ]; then
    model_with_brackets="[${model_display}]"
fi

if [ -n "$git_info" ] && [ -n "$env_info" ]; then
    status_line="$git_info | $env_info $model_with_brackets"
elif [ -n "$git_info" ]; then
    status_line="$git_info $model_with_brackets"
elif [ -n "$env_info" ]; then
    status_line="$env_info $model_with_brackets"
else
    status_line="$model_with_brackets"
fi

printf "%b\n" "$status_line"

# Print usage bars with server indicators aligned to the right of first two lines
if [ ${#bars[@]} -gt 0 ] 2>/dev/null; then
    right_items=("$context_display")
    for i in "${!bars[@]}"; do
        if [ -n "${bars[$i]}" ]; then
            if [ -n "${right_items[$i]}" ]; then
                printf "%b  %b\n" "${bars[$i]}" "${right_items[$i]}"
            else
                printf "%b\n" "${bars[$i]}"
            fi
        fi
    done
else
    # No usage bars - show server status on main line
    printf "%b %b\n"
fi
