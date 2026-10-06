#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/collect-timing.sh [--limit N] [--branch BRANCH] [--output FILE] [--job-output FILE]

Collect successful baseline-ci and secure-ci runs, calculate end-to-end
workflow duration, and summarize the duration of each secure-ci job.

Options:
  --limit N       Successful runs per workflow (default: 10)
  --branch NAME   Branch to collect (default: main)
  --output FILE   CSV output path (default: results/timing-results-<UTC timestamp>.csv)
  --job-output FILE
                  Secure job timing output path (default: results/job-timing.tsv)
  -h, --help      Show this help
EOF
}

limit=10
branch=main
output=""
job_output="results/job-timing.tsv"

while (($#)); do
  case "$1" in
    --limit)
      (($# >= 2)) || { echo "Missing value for --limit" >&2; exit 2; }
      limit="$2"
      shift 2
      ;;

    --branch)
      (($# >= 2)) || { echo "Missing value for --branch" >&2; exit 2; }
      branch="$2"
      shift 2
      ;;

    --output)
      (($# >= 2)) || { echo "Missing value for --output" >&2; exit 2; }
      output="$2"
      shift 2
      ;;

    --job-output)
      (($# >= 2)) || { echo "Missing value for --job-output" >&2; exit 2; }
      job_output="$2"
      shift 2
      ;;

    -h|--help)
      usage
      exit 0
      ;;

    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[[ "$limit" =~ ^[1-9][0-9]*$ ]] || {
  echo "--limit must be a positive integer" >&2
  exit 2
}

command -v gh >/dev/null 2>&1 || {
  echo "GitHub CLI (gh) is required." >&2
  exit 1
}

command -v jq >/dev/null 2>&1 || {
  echo "jq is required." >&2
  exit 1
}

gh auth status >/dev/null

repo_root=$(git rev-parse --show-toplevel 2>/dev/null) || {
  echo "Run this script from inside the SupplyChain_Demo repository." >&2
  exit 1
}

cd "$repo_root"

repo_name=$(gh repo view --json nameWithOwner --jq .nameWithOwner)

if [[ -z "$output" ]]; then
  output="results/timing-results-$(date -u +%Y%m%dT%H%M%SZ).csv"
fi

mkdir -p "$(dirname "$output")"
mkdir -p "$(dirname "$job_output")"

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

csv_tmp="$tmp_dir/timings.csv"
job_tmp="$tmp_dir/job-timing.tsv"

printf '%s\n' \
  'workflow,run_id,event,commit,run_url,started_at,completed_at,duration_seconds,conclusion' \
  > "$csv_tmp"

printf 'run_id\tjob\tseconds\n' > "$job_tmp"


for workflow in baseline.yml secure-ci.yml; do

  echo "Collecting: $workflow"

  runs_file="$tmp_dir/${workflow}.json"

  gh run list \
    --workflow "$workflow" \
    --limit 100 \
    --json databaseId,event,headBranch,headSha,url,conclusion,createdAt,updatedAt \
    | jq --arg branch "$branch" --argjson limit "$limit" '
        map(
          select(
            .headBranch == $branch and
            .conclusion == "success"
          )
        )
        | .[:$limit]
      ' \
    > "$runs_file"


  run_count=$(jq 'length' "$runs_file")

  if ((run_count == 0)); then
    echo "No successful runs found for $workflow on branch '$branch'." >&2
    exit 1
  fi

  if ((run_count < limit)); then
    echo "Warning: found $run_count successful run(s); requested $limit." >&2
  fi


  jq -r \
    --arg workflow "$workflow" '
      def epoch:
        sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601;

      .[] |
      [
        $workflow,
        .databaseId,
        .event,
        .headSha,
        .url,
        .createdAt,
        .updatedAt,
        ((.updatedAt | epoch) - (.createdAt | epoch)),
        .conclusion
      ] | @csv
    ' "$runs_file" >> "$csv_tmp"

  if [[ "$workflow" == "secure-ci.yml" ]]; then
    while IFS= read -r run_id; do
      gh api --paginate \
        "repos/$repo_name/actions/runs/$run_id/jobs?per_page=100" \
        | jq -r --arg run_id "$run_id" '
            def epoch:
              sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601;

            .jobs[]
            | select(.started_at != null and .completed_at != null)
            | [
                $run_id,
                .name,
                ((.completed_at | epoch) - (.started_at | epoch))
              ]
            | @tsv
          ' >> "$job_tmp"
    done < <(jq -r '.[].databaseId' "$runs_file")
  fi

done


mv "$csv_tmp" "$output"
mv "$job_tmp" "$job_output"

echo
echo "Timing data saved to: $output"
echo "Secure job timing data saved to: $job_output"
echo

echo "Pipeline wall-clock summary (successful runs only; seconds):"

awk -F, '
  NR > 1 {
    workflow = $1
    gsub(/^"|"$/, "", workflow)

    duration = $8 + 0

    if (workflow == "baseline.yml") {
      n_base++

      delta = duration - mean_base
      mean_base += delta / n_base
      m2_base += delta * (duration - mean_base)
    }

    else if (workflow == "secure-ci.yml") {
      n_secure++

      delta = duration - mean_secure
      mean_secure += delta / n_secure
      m2_secure += delta * (duration - mean_secure)
    }
  }

  END {
    if (n_base == 0 || n_secure == 0) {
      print "Could not calculate overhead."
      exit 1
    }

    sd_base = n_base > 1 ? sqrt(m2_base / (n_base - 1)) : 0
    sd_secure = n_secure > 1 ? sqrt(m2_secure / (n_secure - 1)) : 0

    overhead = mean_secure - mean_base

    overhead_pct = mean_base > 0 \
      ? overhead / mean_base * 100 \
      : 0

    printf "%-14s n=%d  mean=%8.1f s  SD=%7.1f s\n",
      "Baseline", n_base, mean_base, sd_base

    printf "%-14s n=%d  mean=%8.1f s  SD=%7.1f s\n",
      "Secure", n_secure, mean_secure, sd_secure

    printf "\nOverhead: %+0.1f seconds (%+0.1f%% of baseline)\n",
      overhead, overhead_pct

    if (n_base < 10 || n_secure < 10) {
      print "\nWarning: collect at least 10 successful runs of each workflow."
    }
  }
' "$output"

echo
echo "Secure-ci job duration summary (seconds):"

awk -F'\t' '
  NR > 1 {
    job = $2
    duration = $3 + 0
    n[job]++
    delta = duration - mean[job]
    mean[job] += delta / n[job]
    m2[job] += delta * (duration - mean[job])
  }

  END {
    for (job in n) {
      total_mean += mean[job]
    }

    if (total_mean == 0) {
      print "No completed secure-ci jobs with timing data."
      exit
    }

    for (job in n) {
      sd = n[job] > 1 ? sqrt(m2[job] / (n[job] - 1)) : 0
      printf "%-40s n=%-3d %6.1f ± %5.1f s  %5.1f%%\n",
        job, n[job], mean[job], sd, 100 * mean[job] / total_mean
    }
  }
' "$job_output"