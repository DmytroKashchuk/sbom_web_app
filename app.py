from flask import Flask, render_template, request
import pandas as pd
import os
import math
from collections import Counter

app = Flask(__name__)
DATA_PATH = os.path.join(os.path.dirname(__file__), 'data', 'MAIN_global2000_complete.csv')
REPO_PATH = os.path.join(os.path.dirname(__file__), 'data', 'repositories_summary_with_zero_libs.csv')
VULN_PATH = os.path.join(os.path.dirname(__file__), 'data', 'libraries_with_detailed_vulnerability_status.csv')
VULN_SUMMARY_PATH = os.path.join(os.path.dirname(__file__), 'data', 'libraries_with_detailed_vulnerability_status.csv')
MAIN_PATH = os.path.join(os.path.dirname(__file__), 'data', 'MAIN_global2000_complete.csv')
REPOS_ZERO_LIBS_PATH = os.path.join(os.path.dirname(__file__), 'data', 'repos_with_zero_libraries.csv')
VULN_ID = os.path.join(os.path.dirname(__file__), 'data', 'vulnerability_summary.csv')
#/Users/dmk6603/Documents/forbes_global_2000/6_main_without_zero_libs/MAIN_global2000_complete.csv
MAIN_NO_Zero_Libs_PATH = os.path.join(os.path.dirname(__file__), 'data', 'MAIN_global2000_complete.csv')


@app.route('/')
def index():
    # 1) read & strip
    df = pd.read_csv(DATA_PATH)
    df.columns = df.columns.str.strip()

    # 2) apply search filter
    search = request.args.get('search', '')
    if search:
        df = df[df['global_company'].str.contains(search, case=False, na=False)]

    # 3) compute site-wide stats
    total_orgs         = len(df)
    orgs_with_profiles = df['github_profile_name'].notna().sum()
    # profiles (with a github_profile_name) that have zero repos
    zero_repo_profiles_df = df[(df['github_profile_name'].notna()) & (df['total_repos'] == 0)]
    orgs_zero_repos    = len(zero_repo_profiles_df)
    # include avatar_url for rendering icons in modal list
    zero_repo_profiles = zero_repo_profiles_df[['global_company','github_profile_name','country','sic','avatar_url']].to_dict('records')
    total_repos        = df['total_repos'].sum()

    # Map profile -> avatar url for quick lookups in templates
    avatar_url_map = df.set_index('github_profile_name')['avatar_url'] if 'avatar_url' in df.columns else pd.Series(dtype=object)

    # Repo-level stats
    repo_df = pd.read_csv(REPO_PATH)
    repo_df.columns = repo_df.columns.str.strip()
    total_analyzed_repos = len(repo_df)
    repos_with_zero_libs = len(pd.read_csv(REPOS_ZERO_LIBS_PATH))

    org_repo_counts = repo_df.groupby('organization').size()\
                         .sort_values(ascending=False).head(10)
    org_star_counts = repo_df.groupby('organization')['stars']\
                         .sum().sort_values(ascending=False).head(10)

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

    # --- profile stats ---
    total_repos    = len(df)
    total_stars    = df['stars'].sum() if 'stars' in df.columns else 0
    total_forks    = df['forks'].sum() if 'forks' in df.columns else 0
    # count repos with zero libraries
    zero_mask      = df['zero_libraries'].astype(str).str.lower() == 'true'
    count_zero_libs = zero_mask.sum()
    # vulnerable repos count and percentage
    vuln_mask      = df['vulnerable_repo'].astype(str).str.lower() == 'yes'
    count_vuln_repos = vuln_mask.sum()
    pct_vuln_repos = round((count_vuln_repos / total_repos * 100), 1) if total_repos else 0
    # active/non-active counts
    active_mask    = df['is_active'].astype(str).str.lower() == 'yes'
    count_active   = active_mask.sum()
    count_non_active = total_repos - count_active
    # ---------------------

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

    return render_template('repos.html',
        records=records, columns=columns, profile=profile,
        page=page, total_pages=total_pages,
        sort_by=sort_by, order=order,
        all_columns=all_columns, selected_cols=selected_cols,
        search=search,
        total_repos=total_repos,
        total_stars=total_stars,
        total_forks=total_forks,
        count_zero_libs=count_zero_libs,
        count_vuln_repos=count_vuln_repos,
        pct_vuln_repos=pct_vuln_repos,
        count_active=count_active,
        count_non_active=count_non_active
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
    sort_by = request.args.get('sort_by'); order = request.args.get('order','asc')
    if sort_by in df.columns:
        df = df.sort_values(by=sort_by, ascending=(order=='asc'))
    page = int(request.args.get('page',1)); per_page=50
    total_pages = math.ceil(len(df)/per_page)
    df = df.iloc[(page-1)*per_page: page*per_page]
    records = df.to_dict('records'); columns = df.columns.tolist()
    return render_template('libs.html',
        records=records, columns=columns, org=org, repo=repo,
        page=page, total_pages=total_pages,
        sort_by=sort_by, order=order)

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
    print(f"Fetching vulnerabilities for {org}/{repo}/{library}")
    df = pd.read_csv(VULN_SUMMARY_PATH)
    df.columns = df.columns.str.strip()
    df = df[(df['organization']==org)&(df['repository']==repo)&(df['library']==library)]
    sort_by = request.args.get('sort_by'); order = request.args.get('order','asc')
    if sort_by in df.columns:
        df = df.sort_values(by=sort_by, ascending=(order=='asc'))
    page = int(request.args.get('page',1)); per_page=50
    total_pages = math.ceil(len(df)/per_page)
    df = df.iloc[(page-1)*per_page: page*per_page]
    records = df.to_dict('records'); columns = df.columns.tolist()
    return render_template('vulnerabilities.html',
        records=records, columns=columns,
        org=org, repo=repo, library=library,
        page=page, total_pages=total_pages,
        sort_by=sort_by, order=order)

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

# Vulnerability propagations page
@app.route('/vulnerability_propagations')
def vulnerability_propagations():
    # List all vulnerabilities with count of unique repositories
    df = pd.read_csv(VULN_SUMMARY_PATH)
    df_id = pd.read_csv(VULN_ID)
    df_id.columns = df_id.columns.str.strip()
    df.columns = df.columns.str.strip()
    # Count unique repositories per vulnerability
    counts = df_id.groupby('vulnerability_id')['repository'].nunique().sort_values(ascending=False)
    # Get package name, installed version, severity & description
    info = df_id[['vulnerability_id', 'package_name', 'installed_version', 'severity', 'description']]
    info = info.drop_duplicates(subset=['vulnerability_id']).set_index('vulnerability_id')
    # Collect unique organizations affected per vulnerability
    orgs = df_id.groupby('vulnerability_id')['Organization'].apply(lambda s: sorted(set(s.dropna())))
    orgs.name = 'organizations'
    # Build DataFrame with counts, info, and org list
    vuln_df = counts.to_frame(name='repo_count').join(info).join(orgs)
    # Convert vulnerability data to records
    vuln_data = vuln_df.reset_index().to_dict('records')
    # Compute top 10 repositories by number of vulnerable libraries
    df_vuln = df[df['is_vulnerable'].astype(str).str.lower() == 'true']
    # Count unique vulnerable libraries per organization and repository
    repo_counts = df_vuln.groupby(['organization', 'repository'])['library'].nunique()
    repo_counts.name = 'vuln_lib_count'
    top_repo_df = repo_counts.sort_values(ascending=False).head(10).reset_index()
    repo_vuln = top_repo_df.to_dict('records')
    # Render template with both datasets
    return render_template('vulnerability_propagations.html', vuln_repos=vuln_data, repo_vuln=repo_vuln)

@app.route('/vuln_repos/<vuln_id>')
def vuln_repos(vuln_id):
    # Show all repositories affected by a given vulnerability
    df = pd.read_csv(VULN_SUMMARY_PATH)
    df_id = pd.read_csv(VULN_ID)
    df_id.columns = df_id.columns.str.strip()
    df.columns = df.columns.str.strip()
    subset = df_id[df_id['vulnerability_id'] == vuln_id]
    # Get unique repos and organizations
    records = subset[['Organization', 'repository']].drop_duplicates().to_dict('records')
    return render_template('vuln_repos.html', vuln_id=vuln_id, records=records)

@app.route('/all_vulnerabilities')
def all_vulnerabilities():
    # Load full vulnerability summary dataset
    df = pd.read_csv(VULN_SUMMARY_PATH)
    df.columns = df.columns.str.strip()
    # Prepare records and column list
    records = df.to_dict('records')
    columns = df.columns.tolist()
    return render_template('all_vulnerabilities.html', records=records, columns=columns)


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

@app.route('/vuln_orgs/<vuln_id>')
def vuln_orgs(vuln_id):
    """List organizations affected by a vulnerability with enriched org details."""
    # Load vulnerability-to-org mapping
    df_id = pd.read_csv(VULN_ID)
    df_id.columns = df_id.columns.str.strip()
    subset = df_id[df_id['vulnerability_id'] == vuln_id]
    orgs = sorted(set(subset['Organization'].dropna()))

    # Load main org dataset for enrichment
    main_df = pd.read_csv(MAIN_PATH)
    main_df.columns = main_df.columns.str.strip()

    # Details for orgs present in main dataset
    details = main_df[main_df['github_profile_name'].isin(orgs)].copy()

    # Count affected repositories per org for this vulnerability
    repo_counts = subset.groupby('Organization')['repository'].nunique()
    details['affected_repo_count'] = details['github_profile_name'].map(repo_counts).fillna(0).astype(int)

    # Include missing orgs not present in main dataset
    present = set(details['github_profile_name'].tolist())
    missing_orgs = [o for o in orgs if o not in present]
    if missing_orgs:
        fallback = pd.DataFrame({'github_profile_name': missing_orgs})
        for col in ['global_company', 'country', 'sic', 'avatar_url']:
            fallback[col] = ''
        fallback['affected_repo_count'] = fallback['github_profile_name'].map(repo_counts).fillna(0).astype(int)
        details = pd.concat([details, fallback], ignore_index=True)

    # Preferred columns to show (only keep those that exist)
    preferred_cols = [
        'github_profile_name', 'global_company', 'country', 'sic', 'avatar_url',
        'affected_repo_count', 'total_repos', 'percentage_vulnerable_repositories'
    ]
    columns = [c for c in preferred_cols if c in details.columns]
    details = details[columns]

    records = details.to_dict('records')
    return render_template('vuln_orgs.html', vuln_id=vuln_id, records=records, columns=columns)

if __name__=='__main__':
    app.run(host='127.0.0.1', port=7777, debug=True)


