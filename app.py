from flask import Flask, render_template, request
import pandas as pd
import os
import math
from collections import Counter
import json  # added
import numpy as np  # NEW
import re

app = Flask(__name__)
DATA_PATH = "data/MAIN_global2000_complete.csv"
REPO_PATH = "data/repositories_summary_with_zero_libs.csv"
VULN_PATH = "data/libraries_with_detailed_vulnerability_status.csv"
VULN_SUMMARY_PATH = "data/libraries_with_detailed_vulnerability_status.csv"
MAIN_PATH = "data/MAIN_global2000_complete.csv"
REPOS_ZERO_LIBS_PATH = "data/repos_with_zero_libraries.csv"
RAW_REPOS_DATA_PATH = "data/raw_repos_data.csv"
VULN_ID = "data/vulnerability_summary.csv"
#/Users/dmk6603/Documents/forbes_global_2000/6_main_without_zero_libs/MAIN_global2000_complete.csv
MAIN_NO_Zero_Libs_PATH = "data/MAIN_global2000_complete.csv"
AFFECTED_LIB_VERSIONS_PATH = "data/affected_orgs/affected_orgs_affected_by_lib_version.csv"
AFFECTED_LIBS_PATH = "data/affected_orgs/affected_orgs_affected_by_lib.csv"
PROFILES_SUMMARY_PATH = "data/profiles_summary_complete.csv"


@app.route('/')
def index():
    # 1) read & strip
    df = pd.read_csv(DATA_PATH)
    df.columns = df.columns.str.strip()

    # 2) apply search filter
    search = request.args.get('search', '')
    if search:
        df = df[df['global_company'].str.contains(search, case=False, na=False)]

    # Ensure numeric metrics are clean for aggregation
    for col in ['total_repos', 'total_stars']:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

    # 3) compute site-wide stats
    total_orgs         = len(df)
    orgs_with_profiles = df['github_profile_name'].notna().sum()
    # profiles (with a github_profile_name) that have zero repos
    zero_repo_profiles_df = df[(df['github_profile_name'].notna()) & (df['total_repos'] == 0)]
    orgs_zero_repos    = len(zero_repo_profiles_df)
    # include avatar_url for rendering icons in modal list
    zero_repo_profiles = zero_repo_profiles_df[['global_company','github_profile_name','country','sic','avatar_url']].to_dict('records')
    total_repos        = df['total_repos'].sum()

    # Tech vs Non-Tech breakdown
    is_tech_series = df['is_tech_company'].astype(str).str.strip().str.lower()
    tech_orgs = int((is_tech_series == 'true').sum())
    non_tech_orgs = int((is_tech_series == 'false').sum())
    unknown_orgs = total_orgs - tech_orgs - non_tech_orgs
    tech_pct = (tech_orgs / total_orgs * 100) if total_orgs else 0
    non_tech_pct = (non_tech_orgs / total_orgs * 100) if total_orgs else 0

    # Map profile -> avatar url for quick lookups in templates
    avatar_url_map = df.set_index('github_profile_name')['avatar_url'] if 'avatar_url' in df.columns else pd.Series(dtype=object)

    # Repo-level stats
    repo_df = pd.read_csv(REPO_PATH)
    repo_df.columns = repo_df.columns.str.strip()
    total_analyzed_repos = len(repo_df)
    repos_with_zero_libs = len(pd.read_csv(REPOS_ZERO_LIBS_PATH))

    profile_mask = df['github_profile_name'].notna()
    org_repo_counts_series = (
        df[profile_mask]
        .groupby('github_profile_name')['total_repos']
        .sum()
        .sort_values(ascending=False)
        .head(10)
    )
    org_star_counts_series = (
        df[profile_mask]
        .groupby('github_profile_name')['total_stars']
        .sum()
        .sort_values(ascending=False)
        .head(10)
    )

    org_repo_counts = {idx: int(value) for idx, value in org_repo_counts_series.items()}
    org_star_counts = {idx: int(value) for idx, value in org_star_counts_series.items()}

    # Top languages on full filtered df
    lang_counts = {}
    for langs in df['primary_languages'].dropna():
        for lang in str(langs).split(', '):
            lang_counts[lang] = lang_counts.get(lang, 0) + 1
    top_languages = sorted(lang_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    # Compute top-10 SIC codes (by total companies)
    top_sic = Counter(df['sic'].dropna()).most_common(10)

    # Compute how many companies in each top SIC have a GitHub profile
    profile_counter = Counter(df[df['github_profile_name'].notna()]['sic'].dropna())
    top_sic_profiles = [profile_counter.get(sic, 0) for sic, _ in top_sic]
    
    # Compute total repositories by SIC code
    sic_repo_totals = []
    for sic_code, _ in top_sic:
        sic_companies = df[df['sic'] == sic_code]
        total_repos_for_sic = sic_companies['total_repos'].sum() if 'total_repos' in sic_companies.columns else 0
        sic_repo_totals.append(total_repos_for_sic)

    # Column selection (client wants ability to hide/show)
    all_columns = df.columns.tolist()
    selected_cols = request.args.getlist('columns')
    if selected_cols:
        display_cols = [c for c in all_columns if c in selected_cols]
    else:
        display_cols = all_columns

    # 4) sorting & pagination
    sort_by = request.args.get('sort_by')
    order   = request.args.get('order', 'asc')
    if sort_by in df.columns:
        df = df.sort_values(by=sort_by, ascending=(order == 'asc'))

    # Client-side pagination: send all rows
    page       = 1
    total_pages= 1
    records    = df.to_dict('records')

    # 5) render template
    return render_template('index.html',
        records=records,
        columns=display_cols,
        all_columns=all_columns,
        selected_cols=selected_cols,
        search=search,
        page=page,
        total_pages=total_pages,
        sort_by=sort_by,
        order=order,

        total_orgs=total_orgs,
        orgs_with_profiles=orgs_with_profiles,
        orgs_zero_repos=orgs_zero_repos,
        zero_repo_profiles=zero_repo_profiles,
        total_repos=total_repos,
    total_analyzed_repos=total_analyzed_repos,
        repos_with_zero_libs=repos_with_zero_libs,

    tech_orgs=tech_orgs,
    non_tech_orgs=non_tech_orgs,
    unknown_orgs=unknown_orgs,
    tech_pct=tech_pct,
    non_tech_pct=non_tech_pct,

        org_repo_counts=org_repo_counts,
        org_star_counts=org_star_counts,
        top_languages=top_languages,
        top_countries=Counter(df['country'].dropna()).most_common(10),

        top_sic=top_sic,
        top_sic_profiles=top_sic_profiles,
        top_sic_repos=sic_repo_totals,
        avatar_url_map=avatar_url_map
    )

@app.route('/repos/<profile>')
def repos(profile):
    df = pd.read_csv(REPO_PATH)
    df.columns = df.columns.str.strip()             # strip whitespace
    df = df[df['organization'] == profile]

    # Optional filter: show only repositories that use a specific library/version
    selected_library = request.args.get('library', '').strip()
    selected_version = request.args.get('version', '').strip()
    if selected_library:
        try:
            libs_df = pd.read_csv(VULN_PATH)
            libs_df.columns = libs_df.columns.str.strip()
            # Normalize fields used for matching
            for col in ['organization', 'library', 'version', 'repository']:
                if col in libs_df.columns:
                    libs_df[col] = libs_df[col].astype(str).str.strip()
            mask = (libs_df.get('organization', '').str.casefold() == profile.casefold()) & (libs_df.get('library', '').str.casefold() == selected_library.casefold())
            if selected_version:
                mask &= (libs_df.get('version', '').str.casefold() == selected_version.casefold())
            repo_list = sorted({r for r in libs_df.loc[mask, 'repository'] if isinstance(r, str) and r}) if 'repository' in libs_df.columns else []
            if repo_list:
                # Filter repos dataframe to only those repositories
                if 'repository_name' in df.columns:
                    df = df[df['repository_name'].isin(repo_list)]
                elif 'repository' in df.columns:
                    df = df[df['repository'].isin(repo_list)]
            else:
                # No matching repos; show empty
                df = df.iloc[0:0]
        except Exception:
            # On any failure, keep original df unfiltered
            pass

    # Company metadata (avatar, display name)
    company_avatar = None
    company_name = None
    try:
        main_meta = pd.read_csv(MAIN_PATH)
        main_meta.columns = main_meta.columns.str.strip()
        meta_row = main_meta[main_meta['github_profile_name'] == profile]
        if not meta_row.empty:
            company_avatar = meta_row['avatar_url'].iloc[0]
            company_name = meta_row['global_company'].iloc[0]
    except FileNotFoundError:
        pass
    except Exception:
        # silently continue if metadata lookup fails to avoid breaking page rendering
        pass
    company_avatar = company_avatar if pd.notna(company_avatar) else None
    company_name = company_name if pd.notna(company_name) else None

    # --- profile stats ---
    total_repos    = len(df)
    total_stars    = df['stars'].sum() if 'stars' in df.columns else 0
    total_forks    = df['forks'].sum() if 'forks' in df.columns else 0
    zero_mask      = df['zero_libraries'].astype(str).str.lower() == 'true'
    count_zero_libs = zero_mask.sum()
    vuln_mask      = df['vulnerable_repo'].astype(str).str.lower() == 'yes'
    count_vuln_repos = vuln_mask.sum()
    pct_vuln_repos = round((count_vuln_repos / total_repos * 100), 1) if total_repos else 0
    active_mask    = df['is_active'].astype(str).str.lower() == 'yes'
    count_active   = active_mask.sum()
    count_non_active = total_repos - count_active
    # ---------------------

    # search filter (server side pre-filter)
    search = request.args.get('search', '')
    if search:
        # apply to repository_name and description (if exists)
        mask = df['repository_name'].str.contains(search, case=False, na=False)
        if 'description' in df.columns:
            mask = mask | df['description'].str.contains(search, case=False, na=False)
        df = df[mask]

    # client chooses columns to display
    all_columns = df.columns.tolist()
    selected_cols = request.args.getlist('columns')
    if selected_cols:
        columns = [c for c in all_columns if c in selected_cols]
    else:
        columns = all_columns

    # IMPORTANT: Remove server-side sorting & pagination so Tabulator can sort ALL rows.
    # (Keep query params for backward compat but ignore them here.)
    sort_by = request.args.get('sort_by')  # unused now
    order = request.args.get('order', 'asc')  # unused now

    # Send ALL rows to client; Tabulator will handle virtual DOM, sorting, pagination if desired.
    records = df.to_dict('records')

    return render_template('repos.html',
        records=records,
        columns=columns,
        profile=profile,
        selected_library=selected_library,
        selected_version=selected_version,
        # deprecated pagination/sorting vars kept for template compatibility
        page=1,
        total_pages=1,
        sort_by=sort_by,
        order=order,
        all_columns=all_columns,
        selected_cols=selected_cols,
        search=search,
        total_repos=total_repos,
        total_stars=total_stars,
        total_forks=total_forks,
        count_zero_libs=count_zero_libs,
        count_vuln_repos=count_vuln_repos,
        pct_vuln_repos=pct_vuln_repos,
        count_active=count_active,
        count_non_active=count_non_active,
        company_avatar=company_avatar,
        company_name=company_name
    )

@app.route('/repos/<profile>/zero-libraries')
def zero_libraries_repos(profile):
    """Show only repositories with zero libraries for a specific organization"""
    df = pd.read_csv(REPO_PATH)
    df.columns = df.columns.str.strip()
    df = df[df['organization'] == profile]
    
    # Filter for only zero-library repos
    zero_mask = df['zero_libraries'].astype(str).str.lower() == 'true'
    df = df[zero_mask]

    # search filter
    search = request.args.get('search', '')
    if search:
        df = df[df['repository_name'].str.contains(search, case=False, na=False)]

    # column selection
    all_columns = df.columns.tolist()
    selected_cols = request.args.getlist('columns')
    if selected_cols:
        columns = [c for c in all_columns if c in selected_cols]
    else:
        columns = all_columns

    # sorting
    sort_by = request.args.get('sort_by'); order = request.args.get('order','asc')
    if sort_by in df.columns:
        df = df.sort_values(by=sort_by, ascending=(order=='asc'))

    # pagination
    page = int(request.args.get('page',1)); per_page=50
    total_pages = math.ceil(len(df)/per_page)
    df = df.iloc[(page-1)*per_page: page*per_page]
    records = df.to_dict('records')

    return render_template('zero_libraries_repos.html',
        records=records, columns=columns, profile=profile,
        page=page, total_pages=total_pages,
        sort_by=sort_by, order=order,
        all_columns=all_columns, selected_cols=selected_cols,
        search=search,
        total_zero_repos=len(df)
    )

@app.route('/libs/<org>/<repo>')
def libs(org, repo):
    df = pd.read_csv(VULN_PATH)
    df.columns = df.columns.str.strip()
    df = df[(df['organization']==org)&(df['repository']==repo)]
    # summary stats
    total_libs = len(df)
    vuln_mask = df['is_vulnerable'].astype(str).str.lower() == 'true'
    vuln_count = vuln_mask.sum()
    vuln_pct = round((vuln_count / total_libs * 100), 2) if total_libs else 0

    # optional server-side sorting (Tabulator can also sort client-side)
    sort_by = request.args.get('sort_by'); order = request.args.get('order','asc')
    if sort_by in df.columns:
        df = df.sort_values(by=sort_by, ascending=(order=='asc'))

    # Replace NaN/NaT with None so JSON is valid (avoid bare NaN which breaks JSON.parse)
    df = df.where(df.notnull(), None)

    # if JSON requested (for async reload)
    if request.args.get('format') == 'json':
        return {
            'organization': org,
            'repository': repo,
            'total_libraries': total_libs,
            'vulnerable_libraries': vuln_count,
            'vulnerable_percentage': vuln_pct,
            'data': df.to_dict(orient='records')
        }

    repo_details = None
    try:
        repo_meta = pd.read_csv(REPO_PATH)
        repo_meta.columns = repo_meta.columns.str.strip()

        if 'organization' in repo_meta.columns:
            normalized_org = repo_meta['organization'].astype(str).str.strip().str.casefold()
            org_mask = normalized_org == org.casefold()
            candidates = repo_meta[org_mask]
        else:
            candidates = repo_meta

        if not candidates.empty:
            def norm_series(series):
                return series.astype(str).str.strip().str.casefold()

            match_mask = pd.Series(False, index=candidates.index)
            if 'repository' in candidates.columns:
                match_mask = match_mask | (norm_series(candidates['repository']) == repo.casefold())
            if 'repository_name' in candidates.columns:
                match_mask = match_mask | (norm_series(candidates['repository_name']) == repo.casefold())
            if 'full_name' in candidates.columns:
                target_full = f"{org}/{repo}".casefold()
                match_mask = match_mask | (norm_series(candidates['full_name']) == target_full)

            matches = candidates[match_mask]

            if not matches.empty:
                row = matches.iloc[0]

                def safe_str_val(value):
                    if pd.isna(value):
                        return None
                    if isinstance(value, str):
                        stripped = value.strip()
                        return stripped or None
                    return str(value)

                def safe_int(value):
                    if pd.isna(value):
                        return None
                    try:
                        return int(float(value))
                    except (TypeError, ValueError):
                        return None

                def safe_bool(value, true_value='yes'):
                    if pd.isna(value):
                        return None
                    return str(value).strip().lower() == true_value

                repo_details = {
                    'full_name': safe_str_val(row.get('full_name')) or f"{org}/{repo}",
                    'repository_url': safe_str_val(row.get('repository_url')),
                    'description': safe_str_val(row.get('description')),
                    'primary_language': safe_str_val(row.get('primary_language')),
                    'stars': safe_int(row.get('stars')),
                    'forks': safe_int(row.get('forks')),
                    'watchers': safe_int(row.get('watchers')),
                    'open_issues': safe_int(row.get('open_issues')),
                    'is_active': safe_bool(row.get('is_active'), true_value='yes'),
                    'updated_at': safe_str_val(row.get('updated_at')),
                    'created_at': safe_str_val(row.get('created_at')),
                    'days_since_last_update': safe_int(row.get('days_since_last_update')),
                    'vulnerable_repo': safe_bool(row.get('vulnerable_repo'), true_value='yes'),
                    'zero_libraries': safe_bool(row.get('zero_libraries'), true_value='true'),
                    'total_libraries': safe_int(row.get('total_libraries')),
                    'total_unique_libraries': safe_int(row.get('total_unique_libraries'))
                }
    except FileNotFoundError:
        pass
    except Exception:
        pass

    # client-side pagination with Tabulator: send all records
    records = df.to_dict('records')
    columns = df.columns.tolist()
    # Pre-serialize with allow_nan=False to ensure strict JSON
    records_json = json.dumps(records, allow_nan=False, ensure_ascii=False)
    return render_template('libs.html',
        records=records,
        columns=columns,
        org=org,
        repo=repo,
        total_libs=total_libs,
        vuln_count=vuln_count,
        vuln_pct=vuln_pct,
    repo_details=repo_details,
        # legacy vars kept for compatibility
        page=1,
        total_pages=1,
        sort_by=sort_by,
        order=order,
        records_json=records_json
    )


@app.route('/libs/<org>')
def org_libs(org):
    df = pd.read_csv(VULN_PATH)
    df.columns = df.columns.str.strip()
    df = df[df['organization'] == org]

    # Apply optional search filter across library, version, repository, type
    search = request.args.get('search', '')
    if search:
        pattern = re.compile(re.escape(search), re.IGNORECASE)

        def matches(row):
            return any(
                bool(pattern.search(str(row.get(col, '') or '')))
                for col in ['library', 'version', 'repository', 'type']
            )

        df = df[df.apply(matches, axis=1)]

    # Replace NaNs for safe JSON serialization
    df = df.where(df.notnull(), None)

    total_records = len(df)
    unique_libraries = int(df['library'].nunique()) if total_records else 0
    unique_versions = int(df[['library', 'version']].drop_duplicates().shape[0]) if total_records else 0
    total_repositories = int(df['repository'].nunique()) if total_records else 0

    vuln_mask = df['is_vulnerable'].astype(str).str.lower() == 'true'
    vulnerable_records = int(vuln_mask.sum()) if total_records else 0
    vulnerable_libraries = int(df.loc[vuln_mask, 'library'].nunique()) if total_records else 0
    vulnerable_repositories = int(df.loc[vuln_mask, 'repository'].nunique()) if total_records else 0
    vuln_percentage = round((vulnerable_records / total_records * 100), 2) if total_records else 0

    severity_counts = (
        df.loc[vuln_mask, 'severities']
        .dropna()
        .apply(lambda s: [part.strip() for part in str(s).split(',') if part.strip()])
        .explode()
        .value_counts()
        .to_dict()
    ) if total_records else {}

    library_repo_counts = (
        df.groupby('library')['repository']
        .nunique()
        .sort_values(ascending=False)
        .head(12)
        .to_dict()
    ) if total_records else {}

    type_distribution = (
        df['type']
        .dropna()
        .value_counts()
        .to_dict()
    ) if total_records else {}

    # company metadata
    company_avatar = None
    company_name = None
    try:
        main_meta = pd.read_csv(MAIN_PATH)
        main_meta.columns = main_meta.columns.str.strip()
        meta_row = main_meta[main_meta['github_profile_name'] == org]
        if not meta_row.empty:
            company_avatar = meta_row['avatar_url'].iloc[0]
            company_name = meta_row['global_company'].iloc[0]
    except FileNotFoundError:
        pass
    except Exception:
        pass
    company_avatar = company_avatar if company_avatar and pd.notna(company_avatar) else None
    company_name = company_name if company_name and pd.notna(company_name) else None

    records = df.to_dict('records') if total_records else []
    columns = list(df.columns) if total_records else []
    records_json = json.dumps(records, allow_nan=False, ensure_ascii=False)

    return render_template(
        'org_libs.html',
        org=org,
        company_name=company_name,
        company_avatar=company_avatar,
        search=search,
        total_records=total_records,
        unique_libraries=unique_libraries,
        unique_versions=unique_versions,
        total_repositories=total_repositories,
        vulnerable_records=vulnerable_records,
        vulnerable_libraries=vulnerable_libraries,
        vulnerable_repositories=vulnerable_repositories,
        vuln_percentage=vuln_percentage,
        severity_counts=severity_counts,
        library_repo_counts=library_repo_counts,
        type_distribution=type_distribution,
        records=records,
        records_json=records_json,
        columns=columns
    )

@app.route('/main')
def main():

    df = pd.read_csv(MAIN_NO_Zero_Libs_PATH)
    df.columns = df.columns.str.strip()

    # now you never even loaded ‘market_cap’!

    # convert the percentage column to numeric, just to be safe
    df['percentage_vulnerable_repositories'] = pd.to_numeric(
        df['percentage_vulnerable_repositories'],
        errors='coerce'
    ).fillna(0)

    # select tech companies where is_tech_company is True
    df_tech = df[df['is_tech_company'] == True]
    df_non_tech = df[df['is_tech_company'] == False]
    # get threshold param
    threshold = int(request.args.get('threshold', 10))

    # vulnerability percentages from main data
    metrics_df = df[df['total_repos']>=threshold] if threshold>0 else df
    print(metrics_df.head())
    # select tech companies where is_tech_company is True
    metrics_df_tech_companies = metrics_df[metrics_df['is_tech_company'] == True]
    metrics_df_non_tech_companies = metrics_df[metrics_df['is_tech_company'] == False]
    pct_tech = metrics_df_tech_companies.set_index('github_profile_name')['percentage_vulnerable_repositories']
    pct_non_tech = metrics_df_non_tech_companies.set_index('github_profile_name')['percentage_vulnerable_repositories']


    global_company = metrics_df.set_index('github_profile_name')['global_company']
    most_vuln_tech_top10  = pct_tech.nlargest(10)
    least_vuln_tech_top10 = pct_tech.nsmallest(10)
    most_vuln_non_tech_top10  = pct_non_tech.nlargest(10)
    least_vuln_non_tech_top10 = pct_non_tech.nsmallest(10)
    # Map of avatar URLs for orgs (github_profile_name -> avatar_url)
    avatar_url_map = metrics_df.set_index('github_profile_name')['avatar_url']

    # search filter
    search = request.args.get('search', '')
    if search:
        df = df[df['global_company'].str.contains(search, case=False, na=False)]

    # column selection
    all_columns = df.columns.tolist()
    selected_cols = request.args.getlist('columns')
    columns = selected_cols if selected_cols else all_columns

    # sorting (optional - can be handled by Tabulator instead)
    sort_by = request.args.get('sort_by')
    order = request.args.get('order','asc')
    if sort_by in df.columns:
        df = df.sort_values(by=sort_by, ascending=(order=='asc'))

    # NO PAGINATION - send all records to client
    records = df.to_dict('records')
    
    # Still calculate these for compatibility with template
    page = int(request.args.get('page',1))
    total_pages = 1  # Not used with client-side pagination

    # compute repo-level summary stats across all repositories
    repo_df = pd.read_csv(REPO_PATH)
    repo_df.columns = repo_df.columns.str.strip()
    mask_active = repo_df['is_active'].astype(str).str.lower() == 'yes'
    mask_vuln   = repo_df['vulnerable_repo'].astype(str).str.lower() == 'yes'
    # counts
    active_repo_count   = mask_active.sum()
    inactive_repo_count = (~mask_active).sum()
    active_vuln_count   = (mask_active & mask_vuln).sum()
    inactive_vuln_count = ((~mask_active) & mask_vuln).sum()
    # percentages
    active_vuln_pct   = round((active_vuln_count / active_repo_count * 100), 1) if active_repo_count else 0
    inactive_vuln_pct = round((inactive_vuln_count / inactive_repo_count * 100), 1) if inactive_repo_count else 0
    # Compute per-org stats for all four categories
    def compute_org_stats(org_list):
        org_repo_df = repo_df[repo_df['organization'].isin(org_list)]
        org_group = org_repo_df.groupby('organization').agg(
            total_repos=('repository_name','count'),
            vuln_repos=('vulnerable_repo', lambda s: (s.astype(str).str.lower()=='yes').sum())
        ).reset_index()
        org_group['non_vuln_repos'] = org_group['total_repos'] - org_group['vuln_repos']
        stats_dict = org_group.set_index('organization')[['vuln_repos','non_vuln_repos','total_repos']].to_dict(orient='index')
        
        # Ensure all organizations have stats, even if they have no repos
        for org in org_list:
            if org not in stats_dict:
                stats_dict[org] = {'vuln_repos': 0, 'non_vuln_repos': 0, 'total_repos': 0}
        
        return stats_dict
    
    # Stats for all four categories
    tech_stats = compute_org_stats(most_vuln_tech_top10.index.tolist())
    least_tech_stats = compute_org_stats(least_vuln_tech_top10.index.tolist())
    non_tech_stats = compute_org_stats(most_vuln_non_tech_top10.index.tolist())
    least_non_tech_stats = compute_org_stats(least_vuln_non_tech_top10.index.tolist())
    return render_template('main.html',
        records=records,
        columns=columns,
        page=page,
        total_pages=total_pages,
        sort_by=sort_by,
        order=order,
        threshold=threshold,
        search=search,
        all_columns=all_columns,
        selected_cols=selected_cols,
        global_company=global_company,
        most_vuln_tech_top10=most_vuln_tech_top10,
        least_vuln_tech_top10=least_vuln_tech_top10,
        most_vuln_non_tech_top10=most_vuln_non_tech_top10,
        least_vuln_non_tech_top10=least_vuln_non_tech_top10,
        # vulnerability summary active vs inactive
        active_repo_count=active_repo_count,
        inactive_repo_count=inactive_repo_count,
        active_vuln_count=active_vuln_count,
        inactive_vuln_count=inactive_vuln_count,
        active_vuln_pct=active_vuln_pct,
        inactive_vuln_pct=inactive_vuln_pct,
        tech_stats=tech_stats,
        least_tech_stats=least_tech_stats,
        non_tech_stats=non_tech_stats,
        least_non_tech_stats=least_non_tech_stats,
        avatar_url_map=avatar_url_map
    )

@app.route('/vulns/<org>/<repo>/<library>')
def vuln_summary(org, repo, library):
    """Show detailed vulnerability rows for a single library in a repository using Tabulator.
    Data source: vulnerability_summary.csv (VULN_ID).
    """
    df = pd.read_csv(VULN_ID)
    df.columns = df.columns.str.strip()
    base_mask = (df['Organization'] == org) & (df['repository'] == repo)
    subset = df[base_mask & (df['package_name'] == library)]
    if subset.empty and 'package_name' in df.columns:
        subset = df[base_mask & (df['package_name'].str.lower() == library.lower())]

    total_rows = len(subset)
    is_vulnerable = total_rows > 0
    vulnerable_rows = total_rows
    severity_counts = {}
    if total_rows and 'severity' in subset.columns:
        severity_counts = (subset['severity'].astype(str).str.strip().replace({'nan': ''}).loc[lambda s: s != ''].value_counts().to_dict())

    # Sanitize problematic floats (inf, -inf) and NaN for strict JSON
    if not subset.empty:
        num_cols = subset.select_dtypes(include=[float, int]).columns
        for c in num_cols:
            subset[c] = subset[c].replace([np.inf, -np.inf], np.nan)
        subset = subset.where(subset.notnull(), None)

    records = subset.to_dict('records') if not subset.empty else []
    # Extra safety pass (covers any lingering Python float('inf'))
    for rec in records:
        for k, v in list(rec.items()):
            if isinstance(v, float):
                if math.isnan(v) or math.isinf(v):
                    rec[k] = None

    columns = subset.columns.tolist() if not subset.empty else []
    records_json = json.dumps(records, allow_nan=False)

    # Optional JSON API
    if request.args.get('format') == 'json':
        return {
            'organization': org,
            'repository': repo,
            'library': library,
            'total_rows': total_rows,
            'is_vulnerable': is_vulnerable,
            'vulnerable_rows': vulnerable_rows,
            'severity_counts': severity_counts,
            'data': records
        }

    return render_template('vulnerabilities.html',
        org=org,
        repo=repo,
        library=library,
        total_rows=total_rows,
        is_vulnerable=is_vulnerable,
        vulnerable_rows=vulnerable_rows,
        severity_counts=severity_counts,
        records_json=records_json,
        columns=columns
    )

@app.route('/main_all_libs')
def main_all_libs():

    df = pd.read_csv(MAIN_PATH)
    # select only rows with total_libraries > 0
    df = df[df['total_libraries'] > 0]

    df.columns = df.columns.str.strip()

    # now you never even loaded ‘market_cap’!

    # convert the percentage column to numeric, just to be safe
    df['percentage_vulnerable_repositories'] = pd.to_numeric(
        df['percentage_vulnerable_repositories'],
        errors='coerce'
    ).fillna(0)

    # select tech companies where is_tech_company is True
    df_tech = df[df['is_tech_company'] == True]
    df_non_tech = df[df['is_tech_company'] == False]
    # get threshold param
    threshold = int(request.args.get('threshold', 10))

    # vulnerability percentages from main data
    metrics_df = df[df['total_repos']>=threshold] if threshold>0 else df
    print(metrics_df.head())
    # select tech companies where is_tech_company is True
    metrics_df_tech_companies = metrics_df[metrics_df['is_tech_company'] == True]
    metrics_df_non_tech_companies = metrics_df[metrics_df['is_tech_company'] == False]
    pct_tech = metrics_df_tech_companies.set_index('github_profile_name')['percentage_vulnerable_repositories']
    pct_non_tech = metrics_df_non_tech_companies.set_index('github_profile_name')['percentage_vulnerable_repositories']


    global_company = metrics_df.set_index('github_profile_name')['global_company']
    most_vuln_tech_top10  = pct_tech.nlargest(10)
    least_vuln_tech_top10 = pct_tech.nsmallest(10)
    most_vuln_non_tech_top10  = pct_non_tech.nlargest(10)
    least_vuln_non_tech_top10 = pct_non_tech.nsmallest(10)
    # Map of avatar URLs for orgs (github_profile_name -> avatar_url)
    avatar_url_map = metrics_df.set_index('github_profile_name')['avatar_url']

    # search filter
    search = request.args.get('search', '')
    if search:
        df = df[df['global_company'].str.contains(search, case=False, na=False)]

    # column selection
    all_columns = df.columns.tolist()
    selected_cols = request.args.getlist('columns')
    columns = selected_cols if selected_cols else all_columns

    # sorting (optional - can be handled by Tabulator instead)
    sort_by = request.args.get('sort_by')
    order = request.args.get('order','asc')
    if sort_by in df.columns:
        df = df.sort_values(by=sort_by, ascending=(order=='asc'))

    # NO PAGINATION - send all records to client
    records = df.to_dict('records')
    
    # Still calculate these for compatibility with template
    page = int(request.args.get('page',1))
    total_pages = 1  # Not used with client-side pagination

    # compute repo-level summary stats across all repositories
    repo_df = pd.read_csv(REPO_PATH)
    repo_df.columns = repo_df.columns.str.strip()
    mask_active = repo_df['is_active'].astype(str).str.lower() == 'yes'
    mask_vuln   = repo_df['vulnerable_repo'].astype(str).str.lower() == 'yes'
    # counts
    active_repo_count   = mask_active.sum()
    inactive_repo_count = (~mask_active).sum()
    active_vuln_count   = (mask_active & mask_vuln).sum()
    inactive_vuln_count = ((~mask_active) & mask_vuln).sum()
    # percentages
    active_vuln_pct   = round((active_vuln_count / active_repo_count * 100), 1) if active_repo_count else 0
    inactive_vuln_pct = round((inactive_vuln_count / inactive_repo_count * 100), 1) if inactive_repo_count else 0
    # Compute per-org stats for all four categories
    def compute_org_stats(org_list):
        org_repo_df = repo_df[repo_df['organization'].isin(org_list)]
        org_group = org_repo_df.groupby('organization').agg(
            total_repos=('repository_name','count'),
            vuln_repos=('vulnerable_repo', lambda s: (s.astype(str).str.lower()=='yes').sum())
        ).reset_index()
        org_group['non_vuln_repos'] = org_group['total_repos'] - org_group['vuln_repos']
        stats_dict = org_group.set_index('organization')[['vuln_repos','non_vuln_repos','total_repos']].to_dict(orient='index')
        
        # Ensure all organizations have stats, even if they have no repos
        for org in org_list:
            if org not in stats_dict:
                stats_dict[org] = {'vuln_repos': 0, 'non_vuln_repos': 0, 'total_repos': 0}
        
        return stats_dict
    
    # Stats for all four categories
    tech_stats = compute_org_stats(most_vuln_tech_top10.index.tolist())
    least_tech_stats = compute_org_stats(least_vuln_tech_top10.index.tolist())
    non_tech_stats = compute_org_stats(most_vuln_non_tech_top10.index.tolist())
    least_non_tech_stats = compute_org_stats(least_vuln_non_tech_top10.index.tolist())
    return render_template('main.html',
        records=records,
        columns=columns,
        page=page,
        total_pages=total_pages,
        sort_by=sort_by,
        order=order,
        threshold=threshold,
        search=search,
        all_columns=all_columns,
        selected_cols=selected_cols,
        global_company=global_company,
        most_vuln_tech_top10=most_vuln_tech_top10,
        least_vuln_tech_top10=least_vuln_tech_top10,
        most_vuln_non_tech_top10=most_vuln_non_tech_top10,
        least_vuln_non_tech_top10=least_vuln_non_tech_top10,
        # vulnerability summary active vs inactive
        active_repo_count=active_repo_count,
        inactive_repo_count=inactive_repo_count,
        active_vuln_count=active_vuln_count,
        inactive_vuln_count=inactive_vuln_count,
        active_vuln_pct=active_vuln_pct,
        inactive_vuln_pct=inactive_vuln_pct,
        tech_stats=tech_stats,
        least_tech_stats=least_tech_stats,
        non_tech_stats=non_tech_stats,
        least_non_tech_stats=least_non_tech_stats,
        avatar_url_map=avatar_url_map
    )


@app.route('/all_repos')
def all_repos():
    # load full repo DataFrame and strip whitespace
    df = pd.read_csv(REPO_PATH)
    df.columns = df.columns.str.strip()
    # count repos with zero libraries (value may be string)
    zero_mask = df['zero_libraries'].astype(str).str.lower() == 'true'
    count_zero_libs = zero_mask.sum()
    # filter by zero_libs flag if requested
    zero_libs = request.args.get('zero_libs')
    if zero_libs:
        df = df[zero_mask]
    # filter by active and vulnerable flags if requested
    active_filter = request.args.get('active')
    if active_filter:
        mask_active = df['is_active'].astype(str).str.lower() == 'yes'
        if active_filter.lower() == 'yes':
            df = df[mask_active]
        elif active_filter.lower() == 'no':
            df = df[~mask_active]
    vuln_filter = request.args.get('vulnerable')
    if vuln_filter and vuln_filter.lower() == 'yes':
        mask_vuln = df['vulnerable_repo'].astype(str).str.lower() == 'yes'
        df = df[mask_vuln]
    # compute full-set stats
    vuln_mask = df['vulnerable_repo'].astype(str).str.lower() == 'yes'
    vuln_count = vuln_mask.sum()
    vuln_pct = round((vuln_count / len(df) * 100), 1) if len(df) else 0
    active_mask = df['is_active'].astype(str).str.lower() == 'yes'
    active_count = active_mask.sum()
    non_active_count = len(df) - active_count
    sort_by = request.args.get('sort_by'); order = request.args.get('order','asc')
    if sort_by in df.columns:
        df = df.sort_values(by=sort_by, ascending=(order=='asc'))
    page = int(request.args.get('page',1)); per_page = 50
    total_pages = math.ceil(len(df)/per_page)
    df = df.iloc[(page-1)*per_page: page*per_page]
    records = df.to_dict('records'); columns = df.columns.tolist()
    return render_template('all_repos.html',
        records=records, columns=columns,
        page=page, total_pages=total_pages,
        sort_by=sort_by, order=order,
        count_zero_libs=count_zero_libs, zero_libs=zero_libs,
        vuln_count=vuln_count, vuln_pct=vuln_pct,
        active_count=active_count, non_active_count=non_active_count)


@app.route('/zero_library_overview')
def zero_library_overview():
    """Overview of repositories with zero declared libraries."""
    df = pd.read_csv(REPO_PATH)
    df.columns = df.columns.str.strip()

    # Keep only repositories flagged with zero libraries (defensive guard)
    if 'zero_libraries' in df.columns:
        zero_mask = df['zero_libraries'].astype(str).str.lower().isin(['true', '1', 'yes'])
        df = df[zero_mask]

    # Ensure numeric fields are converted for aggregations
    numeric_cols = [
        'stars', 'forks', 'watchers', 'open_issues', 'size_gb',
        'days_since_last_update', 'vulnerable_libraries_count',
        'total_libraries', 'total_unique_libraries',
        'total_unique_versions', 'percentage_vulnerable_libraries',
        'percentage_unique_versions'
    ]
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')

    total_repos = len(df)

    def flag_series(column, truthy=('yes', 'true', '1')):
        if column not in df.columns:
            return pd.Series(False, index=df.index)
        return df[column].astype(str).str.lower().isin(truthy)

    active_mask = flag_series('is_active')
    vuln_mask = flag_series('vulnerable_repo')

    active_count = int(active_mask.sum())
    inactive_count = int(total_repos - active_count)
    vulnerable_count = int(vuln_mask.sum())
    clean_count = int(total_repos - vulnerable_count)

    # Aggregations for charts
    top_org_counts = (
        df.groupby('organization')['repository_name']
          .count()
          .sort_values(ascending=False)
          .head(10)
    ) if not df.empty and 'organization' in df.columns else pd.Series(dtype=int)

    language_counts = (
        df['primary_language']
          .dropna()
          .astype(str)
          .value_counts()
          .head(10)
    ) if 'primary_language' in df.columns else pd.Series(dtype=int)

    top_stars = (
        df.sort_values(by='stars', ascending=False)
          .head(8)
          if 'stars' in df.columns else df.head(0)
    )

    # Prepare records for Tabulator table
    columns = df.columns.tolist()
    records = df.replace({np.nan: None}).to_dict('records')

    return render_template(
        'zero_library_overview.html',
        records=records,
        columns=columns,
        total_repos=total_repos,
        active_count=active_count,
        inactive_count=inactive_count,
        vulnerable_count=vulnerable_count,
        clean_count=clean_count,
        top_org_labels=list(top_org_counts.index),
        top_org_values=[int(v) for v in top_org_counts.tolist()],
        language_labels=list(language_counts.index),
        language_values=[int(v) for v in language_counts.tolist()],
        stars_labels=[
            f"{row['organization']}/{row['repository_name']}".strip('/')
            for _, row in top_stars.iterrows()
        ] if not top_stars.empty else [],
        stars_values=[
            int(row['stars']) if not pd.isna(row['stars']) else 0
            for _, row in top_stars.iterrows()
        ] if not top_stars.empty else []
    )

@app.route('/all_libs')
def all_libs():
    df = pd.read_csv(VULN_PATH)
    df.columns = df.columns.str.strip()
    sort_by = request.args.get('sort_by'); order = request.args.get('order','asc')
    if sort_by in df.columns:
        df = df.sort_values(by=sort_by, ascending=(order=='asc'))
    page = int(request.args.get('page',1)); per_page = 50
    total_pages = math.ceil(len(df)/per_page)
    df = df.iloc[(page-1)*per_page: page*per_page]
    records = df.to_dict('records'); columns = df.columns.tolist()
    return render_template('main.html',
        records=records,
        columns=columns,
        page=page,
        total_pages=total_pages,
        sort_by=sort_by,
        order=order,
        threshold=threshold,
        search=search,
        all_columns=all_columns,
        selected_cols=selected_cols,
        global_company=global_company,
        most_vuln_tech_top10=most_vuln_tech_top10,
        least_vuln_tech_top10=least_vuln_tech_top10,
        most_vuln_non_tech_top10=most_vuln_non_tech_top10,
        least_vuln_non_tech_top10=least_vuln_non_tech_top10,
        # overall summary
        active_repo_count=active_repo_count,
        inactive_repo_count=inactive_repo_count,
        active_vuln_count=active_vuln_count,
        inactive_vuln_count=inactive_vuln_count,
        active_vuln_pct=active_vuln_pct,
        inactive_vuln_pct=inactive_vuln_pct
    )
    main_df.columns = main_df.columns.str.strip()
    
    # Calculate org statistics
    total_orgs = len(main_df)
    orgs_with_profiles = main_df['github_profile_name'].notna().sum()
    
    # Count orgs with GitHub profiles but zero repos
    orgs_in_repo = set(df['organization'].unique())
    orgs_with_profiles_list = main_df[main_df['github_profile_name'].notna()]['github_profile_name'].tolist()
    orgs_zero_repos = len([org for org in orgs_with_profiles_list if org not in orgs_in_repo])
    
    # top 10 by each metric (adattare i nomi delle colonne se necessario)
    top_stars = df.nlargest(10, 'stars')
    top_forks = df.nlargest(10, 'forks')
    top_watchers = df.nlargest(10, 'watchers')
    
    return render_template('statistics_repos.html',
        total_orgs=total_orgs,
        orgs_with_profiles=orgs_with_profiles,
        orgs_zero_repos=orgs_zero_repos,
        stars_orgs=top_stars['organization'].tolist(),
        stars_repos=top_stars['repository_name'].tolist(),
        stars_data=top_stars['stars'].tolist(),
        forks_orgs=top_forks['organization'].tolist(),
        forks_repos=top_forks['repository_name'].tolist(),
        forks_data=top_forks['forks'].tolist(),
        watchers_orgs=top_watchers['organization'].tolist(),
        watchers_repos=top_watchers['repository_name'].tolist(),
        watchers_data=top_watchers['watchers'].tolist()
    )

@app.route('/language/<language>')
def orgs_by_language(language):
    main_df = pd.read_csv(MAIN_PATH)
    main_df.columns = main_df.columns.str.strip()
    
    # Filter organizations that use this language
    orgs_using_lang = []
    for _, row in main_df.iterrows():
        if pd.notna(row['primary_languages']):
            langs = str(row['primary_languages']).split(', ')
            if language in [lang.strip() for lang in langs]:
                orgs_using_lang.append({
                    'organization': row['github_profile_name'],
                    'company_name': row['global_company'],
                    'country': row['ACCOUNT_COUNTRY']
                })
    
    # Convert to DataFrame for sorting and pagination
    df = pd.DataFrame(orgs_using_lang)
    if df.empty:
        df = pd.DataFrame(columns=['organization', 'company_name', 'employees', 'country'])
    
    sort_by = request.args.get('sort_by'); order = request.args.get('order','asc')
    if sort_by in df.columns:
        df = df.sort_values(by=sort_by, ascending=(order=='asc'))
    
    page = int(request.args.get('page',1)); per_page = 50
    total_pages = math.ceil(len(df)/per_page)
    df = df.iloc[(page-1)*per_page: page*per_page]
    records = df.to_dict('records'); columns = df.columns.tolist()
    
    return render_template('orgs_by_language.html',
        records=records, columns=columns, language=language,
        page=page, total_pages=total_pages,
        sort_by=sort_by, order=order)

# Vulnerability propagation - library impact (aggregated by library)
@app.route('/vuln_propagation/libraries')
def vuln_propagation_libraries():
    df = pd.read_csv(AFFECTED_LIBS_PATH)
    df.columns = df.columns.str.strip()

    numeric_cols = [
        'affected_organizations',
        'affected_repositories',
        'different_versions',
        'different_paths',
        'different_types',
        'total_vulnerabilities'
    ]
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

    total_rows = int(len(df))
    unique_libraries = int(df['library'].nunique()) if 'library' in df.columns else 0

    limit = total_rows
    table_df = df
    table_records = table_df.to_dict('records')
    table_columns = table_df.columns.tolist()

    existing_numeric_cols = [col for col in numeric_cols if col in df.columns]
    grouped = (
        df.groupby('library')[existing_numeric_cols]
        .sum()
        if {'library'}.issubset(df.columns) and existing_numeric_cols else pd.DataFrame()
    )

    top_orgs_series = grouped['affected_organizations'].sort_values(ascending=False).head(10) if 'affected_organizations' in grouped.columns else pd.Series(dtype=float)
    top_vuln_series = grouped['total_vulnerabilities'].sort_values(ascending=False).head(10) if 'total_vulnerabilities' in grouped.columns else pd.Series(dtype=float)

    summary_metrics = {
        'total_rows': total_rows,
        'unique_libraries': unique_libraries,
        'max_affected_orgs': int(df['affected_organizations'].max()) if 'affected_organizations' in df.columns and total_rows else 0,
        'max_affected_repos': int(df['affected_repositories'].max()) if 'affected_repositories' in df.columns and total_rows else 0,
        'max_total_vulns': int(df['total_vulnerabilities'].max()) if 'total_vulnerabilities' in df.columns and total_rows else 0
    }

    top_orgs_chart = {
        'labels': list(top_orgs_series.index),
        'values': [int(val) for val in top_orgs_series.values]
    }
    top_vuln_chart = {
        'labels': list(top_vuln_series.index),
        'values': [int(val) for val in top_vuln_series.values]
    }

    records_json = json.dumps(table_records, allow_nan=False)

    return render_template(
        'vuln_propagation_libraries.html',
        columns=table_columns,
        table_records=table_records,
        records_json=records_json,
        summary_metrics=summary_metrics,
        top_orgs_chart=top_orgs_chart,
        top_vuln_chart=top_vuln_chart,
        limit=limit,
        total_rows=total_rows,
        display_count=len(table_df)
    )

# Vulnerability propagation - library version impact
@app.route('/vuln_propagation/library_versions')
def vuln_propagation_versions():
    df = pd.read_csv(AFFECTED_LIB_VERSIONS_PATH)
    df.columns = df.columns.str.strip()

    numeric_cols = [
        'affected_organizations',
        'affected_repositories',
        'different_versions',
        'different_paths',
        'different_types',
        'total_vulnerabilities'
    ]
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

    total_rows = int(len(df))
    unique_libraries = int(df['library'].nunique()) if 'library' in df.columns else 0
    unique_library_versions = int(df[['library', 'version']].drop_duplicates().shape[0]) if {'library', 'version'}.issubset(df.columns) else 0

    limit_param = request.args.get('limit')
    if limit_param is None:
        limit = total_rows
    else:
        try:
            limit = int(limit_param)
        except ValueError:
            limit = total_rows
        if limit <= 0 or limit > total_rows:
            limit = total_rows

    table_df = df if limit == total_rows else (
        df.nlargest(limit, 'affected_organizations') if 'affected_organizations' in df.columns else df.head(limit)
    )
    table_records = table_df.to_dict('records')
    table_columns = table_df.columns.tolist()

    top_libraries_series = (
        df.groupby('library')['affected_organizations']
        .sum()
        .sort_values(ascending=False)
        .head(10)
        if 'library' in df.columns and 'affected_organizations' in df.columns else pd.Series(dtype=float)
    )
    top_versions_df = (
        df.nlargest(10, 'affected_repositories')[['library', 'version', 'affected_repositories']]
        if 'affected_repositories' in df.columns else pd.DataFrame()
    )

    top_versions_records = top_versions_df.to_dict('records')
    top_versions_chart = {
        'labels': [f"{rec['library']} {rec['version']}" for rec in top_versions_records],
        'values': [int(rec['affected_repositories']) for rec in top_versions_records]
    }
    top_libraries_chart = {
        'labels': list(top_libraries_series.index),
        'values': [int(val) for val in top_libraries_series.values]
    }

    summary_metrics = {
        'total_rows': total_rows,
        'unique_libraries': unique_libraries,
        'unique_library_versions': unique_library_versions,
        'max_affected_orgs': int(df['affected_organizations'].max()) if 'affected_organizations' in df.columns and total_rows else 0,
        'max_affected_repos': int(df['affected_repositories'].max()) if 'affected_repositories' in df.columns and total_rows else 0
    }

    records_json = json.dumps(table_records, allow_nan=False)

    return render_template(
        'vuln_propagation_versions.html',
        columns=table_columns,
        table_records=table_records,
        records_json=records_json,
        summary_metrics=summary_metrics,
        top_libraries_chart=top_libraries_chart,
        top_versions_chart=top_versions_chart,
        limit=limit,
        total_rows=total_rows,
        display_count=len(table_df)
    )

@app.route('/vuln_propagation/library_versions/orgs')
def vuln_library_version_orgs():
    """Show full company details (as in main page) for organizations affected by a specific
    library (and optional version). Uses Tabulator for a rich table.
    Query params:
      - library (required)
      - version (optional)
    """
    library = request.args.get('library', '').strip()
    version = request.args.get('version', '').strip()

    if not library:
        # minimal guard: redirect to main if missing library
        return render_template('library_version_orgs.html',
                               records_json='[]',
                               columns=[],
                               library=library,
                               version=version,
                               total_orgs=0)

    # Load datasets
    libs_df = pd.read_csv(VULN_PATH)
    libs_df.columns = libs_df.columns.str.strip()
    main_df = pd.read_csv(MAIN_PATH)
    main_df.columns = main_df.columns.str.strip()

    # Normalize fields
    for col in ['library', 'version', 'organization']:
        if col in libs_df.columns:
            libs_df[col] = libs_df[col].astype(str).str.strip()

    # Filter by library and optional version
    mask = libs_df['library'].str.casefold() == library.casefold()
    if version:
        mask &= libs_df['version'].astype(str).str.casefold() == version.casefold()

    orgs = sorted({org for org in libs_df.loc[mask, 'organization'] if isinstance(org, str) and org}) if {'organization'}.issubset(libs_df.columns) else []

    # Compute per-organization repository counts for this library/version
    visible_orgs = orgs
    if {'organization', 'repository'}.issubset(libs_df.columns):
        filtered = libs_df[mask].copy()
        # total repos using library (distinct repositories per org)
        repos_using = (
            filtered.groupby('organization')['repository']
            .nunique()
            .astype(int)
        ) if not filtered.empty else pd.Series(dtype=int)
        # vulnerable repos using library
        vuln_mask = filtered['is_vulnerable'].astype(str).str.lower() == 'true' if 'is_vulnerable' in filtered.columns else pd.Series(False, index=filtered.index)
        vuln_using = (
            filtered[vuln_mask].groupby('organization')['repository']
            .nunique()
            .astype(int)
        ) if not filtered.empty and 'is_vulnerable' in filtered.columns else pd.Series(dtype=int)
    else:
        repos_using = pd.Series(dtype=int)
        vuln_using = pd.Series(dtype=int)

    # Select records from MAIN for these orgs
    if 'github_profile_name' in main_df.columns:
        records_df = main_df[main_df['github_profile_name'].isin(visible_orgs)].copy()
    else:
        records_df = main_df.iloc[0:0].copy()

    # Attach computed metrics
    if not records_df.empty:
        records_df['total_repos_using_library'] = records_df['github_profile_name'].map(repos_using).fillna(0).astype(int)
        records_df['vulnerable_repos_using_library'] = records_df['github_profile_name'].map(vuln_using).fillna(0).astype(int)
    else:
        records_df['total_repos_using_library'] = []
        records_df['vulnerable_repos_using_library'] = []

    # Visible columns (limit as requested); keep extra fields in data for formatters
    visible_columns = [
        'global_company',
        'github_profile',
        'public_repos',
        'total_repos',
        'total_stars',
        'total_forks',
        'total_repos_using_library',
        'vulnerable_repos_using_library'
    ]
    # Filter to only columns that actually exist
    columns = [c for c in visible_columns if c in records_df.columns]

    # Safety: ensure JSON serializable types
    safe_df = records_df.replace([np.inf, -np.inf], np.nan).where(records_df.notnull(), None)
    records = safe_df.to_dict('records')
    records_json = json.dumps(records, allow_nan=False)

    return render_template('library_version_orgs.html',
                           records_json=records_json,
                           columns=columns,
                           library=library,
                           version=version,
                           total_orgs=len(records))


@app.route('/api/library-version/organizations')
def api_library_version_organizations():
    library = request.args.get('library', '').strip()
    version = request.args.get('version', '').strip()

    if not library:
        return {'error': 'library parameter is required'}, 400

    try:
        df = pd.read_csv(VULN_PATH)
    except FileNotFoundError:
        return {'error': 'library dataset unavailable'}, 500

    df.columns = df.columns.str.strip()

    required_cols = {'library', 'version', 'organization'}
    if not required_cols.issubset(df.columns):
        return {
            'library': library,
            'version': version,
            'organizations': [],
            'count': 0
        }

    df['library'] = df['library'].astype(str).str.strip()
    df['version'] = df['version'].astype(str).str.strip()
    df['organization'] = df['organization'].astype(str).str.strip()

    df.loc[df['version'].str.lower().isin({'nan', 'none'}) | (df['version'] == 'nan'), 'version'] = ''
    df.loc[df['organization'].str.lower().isin({'nan', 'none'}) | (df['organization'] == 'nan'), 'organization'] = ''

    mask = df['library'].str.casefold() == library.casefold()
    if version:
        mask &= df['version'].str.casefold() == version.casefold()

    organizations = sorted({org for org in df.loc[mask, 'organization'] if org})

    return {
        'library': library,
        'version': version,
        'organizations': organizations,
        'count': len(organizations)
    }

# Vulnerability propagations page
@app.route('/vulnerability_propagations')
def vulnerability_propagations():
    df_id = pd.read_csv(VULN_ID)
    df_id.columns = df_id.columns.str.strip()

    # Count unique repositories per vulnerability
    counts = df_id.groupby('vulnerability_id')['repository'].nunique().sort_values(ascending=False)
    # Get package name, installed version, severity, description, fixed_version, links
    info_cols = [c for c in ['vulnerability_id', 'package_name', 'installed_version', 'severity', 'description', 'fixed_version', 'links'] if c in df_id.columns]
    info = df_id[info_cols].drop_duplicates(subset=['vulnerability_id']).set_index('vulnerability_id')
    # Org count per vulnerability
    org_counts = df_id.groupby('vulnerability_id')['Organization'].nunique()
    org_counts.name = 'org_count'
    # Build combined DataFrame
    vuln_df = counts.to_frame(name='repo_count').join(info).join(org_counts)
    vuln_df = vuln_df.reset_index()

    # Summary metrics
    total_vulnerabilities = int(vuln_df['vulnerability_id'].nunique()) if not vuln_df.empty else 0
    total_repositories = int(df_id['repository'].nunique()) if 'repository' in df_id.columns else 0
    total_organizations = int(df_id['Organization'].nunique()) if 'Organization' in df_id.columns else 0
    sev_upper = df_id['severity'].astype(str).str.strip().str.lower() if 'severity' in df_id.columns else pd.Series(dtype=str)
    critical_or_high = int(sev_upper.isin(['critical', 'high']).sum()) if not sev_upper.empty else 0

    class SummaryMetrics:
        pass
    summary_metrics = SummaryMetrics()
    summary_metrics.total_vulnerabilities = total_vulnerabilities
    summary_metrics.total_repositories = total_repositories
    summary_metrics.total_organizations = total_organizations
    summary_metrics.critical_or_high = critical_or_high

    # Severity counts for doughnut chart
    severity_counts = {}
    if 'severity' in df_id.columns:
        severity_counts = (
            df_id['severity'].astype(str).str.strip()
            .replace({'nan': 'Unknown', '': 'Unknown'})
            .value_counts()
            .to_dict()
        )

    # Top 10 packages by impacted repo count
    if 'package_name' in df_id.columns and 'repository' in df_id.columns:
        pkg_impact = df_id.groupby('package_name')['repository'].nunique().sort_values(ascending=False).head(10)
        top_packages = {'labels': list(pkg_impact.index), 'values': [int(v) for v in pkg_impact.values]}
    else:
        top_packages = {'labels': [], 'values': []}

    # Replace NaN/inf for JSON safety
    num_cols = vuln_df.select_dtypes(include=[float, int]).columns
    for c in num_cols:
        vuln_df[c] = vuln_df[c].replace([np.inf, -np.inf], np.nan)
    vuln_df = vuln_df.where(vuln_df.notnull(), None)
    records = vuln_df.to_dict('records')
    # Extra pass: convert any remaining numpy types
    for rec in records:
        for k, v in list(rec.items()):
            if isinstance(v, (float,)) and (v != v or v == float('inf') or v == float('-inf')):
                rec[k] = None
            elif isinstance(v, (np.integer,)):
                rec[k] = int(v)
            elif isinstance(v, (np.floating,)):
                rec[k] = float(v) if not (np.isnan(v) or np.isinf(v)) else None
    records_json = json.dumps(records, allow_nan=False)

    return render_template('vulnerability_propagations.html',
        records_json=records_json,
        summary_metrics=summary_metrics,
        severity_counts=severity_counts,
        top_packages=top_packages
    )

# Vulnerability propagations - repository impact view
@app.route('/vulnerability_propagations/repositories')
def vulnerability_propagations_repositories():
    df = pd.read_csv(VULN_SUMMARY_PATH)
    df.columns = df.columns.str.strip()
    df_vuln = df[df['is_vulnerable'].astype(str).str.lower() == 'true']
    repo_counts = df_vuln.groupby(['organization', 'repository'])['library'].nunique()
    repo_counts.name = 'vuln_lib_count'
    top_repo_df = repo_counts.sort_values(ascending=False).head(10).reset_index()
    repo_vuln = top_repo_df.to_dict('records')
    return render_template('vulnerability_propagations_repos.html', repo_vuln=repo_vuln)

@app.route('/vuln_orgs/<vuln_id>')
def vuln_orgs(vuln_id):
    df_id = pd.read_csv(VULN_ID)
    df_id.columns = df_id.columns.str.strip()
    subset = df_id[df_id['vulnerability_id'] == vuln_id].copy()

    main_df = pd.read_csv(MAIN_PATH)
    main_df.columns = main_df.columns.str.strip()

    def clean_key(value: str) -> str:
        value = value.strip()
        return re.sub(r"\s+", "_", value)

    def convert_value(value):
        if pd.isna(value):
            return None
        if isinstance(value, (np.integer, np.int64, np.int32, int)):
            return int(value)
        if isinstance(value, (np.floating, np.float64, np.float32, float)):
            return float(value)
        if isinstance(value, (np.bool_, bool)):
            return bool(value)
        return value

    base_columns = main_df.columns.tolist()
    base_columns_clean = [clean_key(col) for col in base_columns]
    column_map = dict(zip(base_columns, base_columns_clean))

    summary = {
        'total_orgs': 0,
        'matched_orgs': 0,
        'unmatched_orgs': 0,
        'affected_repositories_total': 0,
        'unmatched_names': [],
    }

    if subset.empty or subset['Organization'].dropna().empty:
        columns = list(dict.fromkeys([
            'vulnerability_org_display',
            'affected_repository_count',
            'vulnerability_record_count',
            'severity_levels',
            *base_columns_clean,
        ]))
        return render_template(
            'vuln_orgs.html',
            records_json='[]',
            columns=columns,
            summary=summary,
            vuln_id=vuln_id
        )

    subset['Organization'] = subset['Organization'].astype(str).str.strip()
    subset = subset[subset['Organization'] != '']
    subset['norm_org'] = subset['Organization'].str.lower()

    def summarize_severity(series: pd.Series):
        order = ['Critical', 'High', 'Medium', 'Low']
        values = [str(x).strip() for x in series.dropna() if str(x).strip()]
        if not values:
            return None
        result = []
        for level in order:
            if level in values:
                result.append(level)
        leftovers = sorted({v for v in values if v not in order})
        result.extend(leftovers)
        return ', '.join(result)

    org_agg = subset.groupby('norm_org').agg(
        display_name=('Organization', 'first'),
        affected_repository_count=('repository', lambda s: s.astype(str).str.strip().str.lower().nunique()),
        vulnerability_record_count=('repository', 'size'),
        severity_levels=('severity', summarize_severity)
    ).reset_index()

    candidate_columns = [col for col in ['organization', 'github_profile_name', 'global_company', 'name'] if col in main_df.columns]
    lookup = {}
    for idx, row in main_df.iterrows():
        for col in candidate_columns:
            value = row[col]
            if pd.isna(value):
                continue
            norm = str(value).strip().lower()
            if not norm:
                continue
            lookup.setdefault(norm, idx)

    records = []
    matched_norms = set()
    for _, agg_row in org_agg.iterrows():
        norm = agg_row['norm_org']
        base_record = {clean_key(col): None for col in base_columns}

        if norm in lookup:
            matched_norms.add(norm)
            row = main_df.loc[lookup[norm]]
            for orig_col, clean_col in column_map.items():
                base_record[clean_col] = convert_value(row[orig_col])
        else:
            # fallbacks for organizations not present in main dataset
            if 'global_company' in base_record:
                base_record['global_company'] = agg_row['display_name']
            if 'organization' in base_record:
                base_record['organization'] = agg_row['display_name']

        base_record['vulnerability_org_display'] = agg_row['display_name']
        affected_repos_val = agg_row['affected_repository_count']
        vuln_records_val = agg_row['vulnerability_record_count']
        base_record['affected_repository_count'] = int(affected_repos_val) if pd.notna(affected_repos_val) else 0
        base_record['vulnerability_record_count'] = int(vuln_records_val) if pd.notna(vuln_records_val) else 0
        base_record['severity_levels'] = agg_row['severity_levels']
        records.append(base_record)

    if not records:
        for _, agg_row in org_agg.iterrows():
            base_record = {clean_key(col): None for col in base_columns}
            base_record['vulnerability_org_display'] = agg_row['display_name']
            affected_repos_val = agg_row['affected_repository_count']
            vuln_records_val = agg_row['vulnerability_record_count']
            base_record['affected_repository_count'] = int(affected_repos_val) if pd.notna(affected_repos_val) else 0
            base_record['vulnerability_record_count'] = int(vuln_records_val) if pd.notna(vuln_records_val) else 0
            base_record['severity_levels'] = agg_row['severity_levels']
            records.append(base_record)

    records.sort(key=lambda r: (r.get('affected_repository_count') or 0), reverse=True)

    matched_orgs = len(matched_norms)
    total_orgs = len(org_agg)
    unmatched_orgs = total_orgs - matched_orgs
    unmatched_norms = set(org_agg['norm_org']) - matched_norms
    unmatched_names = sorted(org_agg[org_agg['norm_org'].isin(unmatched_norms)]['display_name'].unique()) if unmatched_norms else []

    summary.update({
        'total_orgs': total_orgs,
        'matched_orgs': matched_orgs,
        'unmatched_orgs': unmatched_orgs,
        'affected_repositories_total': int(org_agg['affected_repository_count'].sum()) if not org_agg.empty else 0,
        'unmatched_names': unmatched_names,
    })

    extra_columns = ['vulnerability_org_display', 'affected_repository_count', 'vulnerability_record_count', 'severity_levels']
    columns = list(dict.fromkeys(extra_columns + base_columns_clean))

    records_json = json.dumps(records, allow_nan=False)

    return render_template('vuln_orgs.html', records_json=records_json, columns=columns, summary=summary, vuln_id=vuln_id)

@app.route('/vuln_repos/<vuln_id>')
def vuln_repos(vuln_id):
    # Show all repositories affected by a given vulnerability (Tabulator-ready)
    df_id = pd.read_csv(VULN_ID)
    df_id.columns = df_id.columns.str.strip()
    subset = df_id[df_id['vulnerability_id'] == vuln_id]

    # Unique repository rows
    repo_df = subset[['Organization', 'repository']].drop_duplicates().rename(columns={'Organization': 'organization'})
    records = repo_df.to_dict('records')

    # Aggregate stats
    total_repos = len(repo_df)
    total_orgs = repo_df['organization'].nunique()
    org_counts = repo_df.groupby('organization').size().reset_index(name='repo_count').sort_values('repo_count', ascending=False)
    top_orgs = org_counts.head(10).to_dict('records')

    # JSON for Tabulator
    records_json = json.dumps(records, allow_nan=False)

    if request.args.get('format') == 'json':
        return {
            'vulnerability_id': vuln_id,
            'total_repositories': total_repos,
            'total_organizations': total_orgs,
            'repositories': records,
            'top_orgs': top_orgs,
        }

    return render_template('vuln_repos.html',
        vuln_id=vuln_id,
        records=records,
        records_json=records_json,
        total_repos=total_repos,
        total_orgs=total_orgs,
        top_orgs=top_orgs
    )

@app.route('/all_vulnerabilities')
def all_vulnerabilities():
    # Load full vulnerability summary dataset
    df = pd.read_csv(VULN_SUMMARY_PATH)
    df.columns = df.columns.str.strip()
    # Prepare records and column list
    records = df.to_dict('records')
    columns = df.columns.tolist()
    return render_template('all_vulnerabilities.html', records=records, columns=columns)


# Raw data: raw repositories dataset
@app.route('/raw/raw_repos')
def raw_repos_data():
    """Render interactive exploration of raw_repos_data.csv focusing on the table only."""
    try:
        df = pd.read_csv(RAW_REPOS_DATA_PATH)
    except FileNotFoundError:
        df = pd.DataFrame()

    def sanitize_records(payload):
        if isinstance(payload, dict):
            return {key: sanitize_records(val) for key, val in payload.items()}
        if isinstance(payload, list):
            return [sanitize_records(item) for item in payload]
        if isinstance(payload, (np.bool_, bool)):
            return bool(payload)
        if isinstance(payload, (np.integer, int)):
            return int(payload)
        if isinstance(payload, (np.floating, float)):
            if pd.isna(payload) or np.isinf(payload):
                return None
            return float(payload)
        return payload

    if df.empty:
        records, columns = [], []
    else:
        df.columns = df.columns.str.strip()
        df = df.replace([np.inf, -np.inf], np.nan)
        records = sanitize_records(df.to_dict('records'))
        columns = df.columns.tolist()

    return render_template('raw_repos_data.html', records=records, columns=columns)


# Raw data: profiles summary
@app.route('/raw/profiles_summary')
def profiles_summary():
    """Render a simple, fast table for profiles_summary_complete.csv using Tabulator."""
    try:
        df = pd.read_csv(PROFILES_SUMMARY_PATH)
    except FileNotFoundError:
        # Fallback: empty table with message columns
        df = pd.DataFrame()

    # Normalize columns and records
    if not df.empty:
        df.columns = df.columns.str.strip()
        # Ensure json-friendly values
        df = df.replace([np.inf, -np.inf], np.nan).where(df.notnull(), None)
        records = df.to_dict('records')
        columns = df.columns.tolist()
    else:
        records = []
        columns = []

    return render_template('profiles_summary.html', records=records, columns=columns)


# Raw data: repositories summary (with zero libs info)
@app.route('/raw/repositories_summary')
def repositories_summary_raw():
    """Render a Tabulator table for repositories_summary_with_zero_libs.csv."""
    try:
        df = pd.read_csv(REPO_PATH)
    except FileNotFoundError:
        df = pd.DataFrame()

    if not df.empty:
        df.columns = df.columns.str.strip()
        # Normalize booleans to strings for consistency
        def as_bool_series(series, true_value):
            return series.astype(str).str.strip().str.lower() == true_value

        vuln_mask = as_bool_series(df.get('vulnerable_repo', pd.Series(dtype=object)), 'yes') if 'vulnerable_repo' in df.columns else pd.Series([], dtype=bool)
        active_mask = as_bool_series(df.get('is_active', pd.Series(dtype=object)), 'yes') if 'is_active' in df.columns else pd.Series([], dtype=bool)
        zero_libs_mask = as_bool_series(df.get('zero_libraries', pd.Series(dtype=object)), 'true') if 'zero_libraries' in df.columns else pd.Series([], dtype=bool)

        metrics = {
            'total_repos': int(len(df)),
            'vuln_count': int(vuln_mask.sum()) if len(df) else 0,
            'active_count': int(active_mask.sum()) if len(df) else 0,
            'inactive_count': int(len(df) - active_mask.sum()) if len(df) else 0,
            'zero_libs_count': int(zero_libs_mask.sum()) if len(df) else 0,
        }

        # Ensure JSON-friendly
        df = df.replace([np.inf, -np.inf], np.nan).where(df.notnull(), None)
        records = df.to_dict('records')
        columns = df.columns.tolist()
    else:
        records, columns = [], []
        metrics = {
            'total_repos': 0,
            'vuln_count': 0,
            'active_count': 0,
            'inactive_count': 0,
            'zero_libs_count': 0,
        }

    return render_template('repositories_summary.html', records=records, columns=columns, metrics=metrics)


if __name__=='__main__':
    app.run(host='0.0.0.0', port=8883)

