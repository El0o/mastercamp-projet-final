### TD Final: Analyse des Avis et Alertes ANSSI avec Enrichissement des CVE

# Importation des librairies
import pandas as pd
import feedparser as fp
import requests as req
import re
from time import sleep
import ssl

### Fixed ValueError with ssl certificate not found
if hasattr(ssl, '_create_unverified_context'):
    ssl._create_default_https_context = ssl._create_unverified_context

## Etape 1 - Extraction des Flux RSS

url_avis = "https://cert.ssi.gouv.fr/avis/feed"
url_alerte = "https://cert.ssi.gouv.fr/alerte/feed"

rss_feed_avis = fp.parse(url_avis)
sleep(2)
rss_feed_alerte = fp.parse(url_alerte)

# Vérification de l'intégrité du flux
if rss_feed_avis.bozo:
    raise ValueError("Echec de l'analyse du feed RSS-AVIS. Vérifiez l'URL.\n")
elif rss_feed_alerte.bozo:
    raise ValueError("Echec de l'analyse du feed RSS-ALERTE. Vérifiez l'URL.\n")
else:
    print(f"Feed RSS-AVIS analysé avec succès (source : {url_avis})\n")
    print(f"Feed RSS-ALERTE analysé avec succès (source : {url_alerte})\n")

rows = []


def get_bulletin_id(ent_id):
    parts = ent_id.split('/')
    bulletin_string = parts[-2]
    return bulletin_string


def clean_title(title_string):
    """
    Supprime tous les textes entre crochets [] ou parenthèses () d'une chaîne de characters donnée.
    """
    cleaned_string = re.sub(r"\(.*?\)", "", title_string)
    cleaned_string = re.sub(r"\[.*?\]", "", cleaned_string)
    cleaned_string = re.sub(r"\s\s+", " ", cleaned_string).strip()

    return cleaned_string


# Collecte des données ANSSI
for entry in rss_feed_avis.entries:
    rows.append({
        "Id": get_bulletin_id(entry.id),
        "Title": clean_title(entry.title),
        "Type": "Avis",
        "Link": entry.link,
        "Summary": entry.summary,
        "Published": entry.published
    })

for entry in rss_feed_alerte.entries:
    rows.append({
        "Id": get_bulletin_id(entry.id),
        "Title": clean_title(entry.title),
        "Type": "Alerte",
        "Link": entry.link,
        "Summary": entry.summary,
        "Published": entry.published
    })

# Conversion en DataFrame
df_flux_rss = pd.DataFrame(rows, columns=["Id", "Title", "Type", "Link", "Published", "Summary"])

# Conversion de la colonne 'Publihed' en datetime
df_flux_rss["Published"] = pd.to_datetime(df_flux_rss["Published"], format="%a, %d %b %Y %H:%M:%S %z", errors='coerce')

# Tri par date de publication
df_flux_rss = df_flux_rss.sort_values(by="Published", ascending=False)


## Etape 2 - Extraction des CVE

def extract_cve_from_link(link, verbose=False):
    json_link = link.rstrip("/") + "/json/"
    sleep(2)
    response = req.get(json_link)
    if response.status_code != 200:
        if verbose:
            print(f"Erreur: impossible d'accéder à {json_link}")
        return []

    try:
        data = response.json()
    except ValueError:
        if verbose:
            print(f"Le contenu de {json_link} n'est pas un JSON valide.")
        return []

    cve_list = [item['name'] for item in data["cves"]]

    if verbose:
        print(f"CVE trouvé: {'✅' if cve_list else '❌'}")

    return cve_list

#extract CVEs from each link in the DataFrame & store them in a new column
df_flux_rss["CVE"] = df_flux_rss["Link"].apply(extract_cve_from_link)


## Etape 3 - Enrichissement des CVE

# Fonction utilitaires de get_api_data

def safe_float(value):
    try:
        return float(value)
    except (ValueError, TypeError):
        return None


def is_actually_null(obj):
    return str(obj).lower().strip() in ['none', 'n/a', 'unspecified', 'null', '[]', '{}', '']


def find_all_by_key(json_data, the_key):
    results = []
    if isinstance(json_data, dict):
        for key, value in json_data.items():
            if key == the_key:
                results.append(value)
            else:
                results.extend(find_all_by_key(value, the_key))
    elif isinstance(json_data, list):
        for item in json_data:
            results.extend(find_all_by_key(item, the_key))
    return results


def find_first_non_null_by_key(json_data, the_key):
    if isinstance(json_data, dict):
        for key, value in json_data.items():
            if key == the_key and not is_actually_null(value):
                return value
            result = find_first_non_null_by_key(value, the_key)
            if not is_actually_null(result):
                return result
    elif isinstance(json_data, list):
        for item in json_data:
            result = find_first_non_null_by_key(item, the_key)
            if not is_actually_null(result):
                return result
    return None


def get_description(cna_adp):
    descriptions = find_first_non_null_by_key(cna_adp, "descriptions")
    if descriptions is None:
        return None
    for d in descriptions:
        if d.get("lang") == "en":
            return d.get("value")
    return None


def get_cvss_metrics(cna_adp):
    metrics = find_first_non_null_by_key(cna_adp, "metrics")
    if not metrics:
        return None, None
    for m in metrics:
        keys = [k for k in m if "cvss" in k]
        for k in keys:
            score = find_first_non_null_by_key(m[k], "baseScore")
            severity = find_first_non_null_by_key(m[k], "baseSeverity")
            if score and severity:
                return safe_float(score), severity
    return None, None


def get_cwes(cna_adp):
    pbs = find_first_non_null_by_key(cna_adp, "problemTypes")
    if not pbs:
        return []
    cwes = []
    for pb in pbs:
        desc = pb.get("descriptions")
        if desc:
            cwes += find_all_by_key(desc, "cweId")
    if cwes:
        return list(set(cwes))
    return []


def normalize_version_string(s):
    patterns = [
        (r"(below|up to|prior to|before|less than)\s+(version\s+)?([\w\.\-\_]+)", r"<= \3"),
        (r"(above|later than|after|greater than)\s+(version\s+)?([\w\.\-\_]+)", r">= \3"),
        (r"\bversion\b", r""),
    ]
    normalized = s
    for pattern, replacement in patterns:
        normalized = re.sub(pattern, replacement, normalized, flags=re.IGNORECASE)
    return normalized.strip()


def process_version(version_dict):
    processed_version = []
    version = version_dict["version"]
    if version:
        if ',' in version:
            processed_version += version.split(',')
        if version_dict.get("lessThan"):
            processed_version += [f"<= {version_dict['lessThan']}"]
        if version_dict.get("greaterThan"):
            processed_version += [f">= {version_dict['greaterThan']}"]
        if not is_actually_null(version):
            processed_version += [version]

        normalized_processed_version = [normalize_version_string(v) for v in processed_version]
        return normalized_processed_version
    return processed_version


def get_affected_products(cna_adp):
    affected = find_first_non_null_by_key(cna_adp, "affected")
    if not affected:
        return []
    prods = []
    for affected in affected:
        vendor = affected.get("vendor")
        product = affected.get("product")
        if not (is_actually_null(vendor) and is_actually_null(product)):
            versions = affected.get("versions", [])
            v_to_keep = []
            for version in versions:
                v_to_keep += process_version(version)
            prods.append({"vendor": vendor, "product": product, "versions": v_to_keep})
    return prods


def get_epss_metrics(data_dict):
    infos = next(iter(data_dict), None)
    if not infos:
        return None, None
    return safe_float(infos.get("epss")), safe_float(infos.get("percentile"))

def get_api_data(cve_id, verbose=None):
    description = None
    cvss_score = None
    base_severity = None
    cwes = set()
    affected_products = []
    epss_score = None
    epss_percentile = None

    # CVE API
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    sleep(2)
    response = req.get(url)

    if response.status_code != 200:
        if verbose:
            print(f"Erreur: impossible d'accéder à l'API CVE pour {cve_id}. Statut: {response.status_code}")
        return None
    try:
        data = response.json()
    except req.exceptions.JSONDecodeError:
        if verbose:
            print(f"Erreur: Impossible de décoder la réponse JSON de l'API CVE pour {cve_id}.")
        return None

    containers = data.get("containers", {})
    CNA = containers.get("cna", {})
    ADP = containers.get("adp", {})
    if CNA or ADP:

        # Description
        description = get_description(CNA)
        if not description:
            description = get_description(ADP)

        # CVSS score & base severity
        cvss_score, base_severity = get_cvss_metrics(CNA)
        if not (cvss_score and base_severity):
            cvss_score, base_severity = get_cvss_metrics(ADP)

        # CWE(s)
        cwes = get_cwes(CNA)
        if not cwes:
            cwes = get_cwes(ADP)

        # Produits et versions affectés
        affected_products = get_affected_products(CNA)
        if not affected_products:
            affected_products = get_affected_products(ADP)

    # EPSS API
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    sleep(2)
    response = req.get(url)

    if response.status_code != 200:
        if verbose:
            print(f"Erreur: impossible d'accéder à l'API EPSS pour {cve_id}. Statut: {response.status_code}")
        return None
    try:
        data = response.json()
    except req.exceptions.JSONDecodeError:
        if verbose:
            print(f"Erreur: Impossible de décoder la réponse JSON de l'API EPSS pour {cve_id}.")
        return None

    # EPSS score & percentile
    d = data.get("data")
    if d:
        epss_score, epss_percentile = get_epss_metrics(d)

    if verbose:
        print(f"Pour {cve_id}:")
        print(f"\tDescription: {'✅' if description else '❌'}")
        print(f"\tCVSS_score: {'✅' if cvss_score else '❌'}")
        print(f"\tBase_severity: {'✅' if base_severity else '❌'}")
        print(f"\tCWE: {'✅' if cwes else '❌'}")
        print(f"\tAffected_products: {'✅' if affected_products else '❌'}")
        print(f"\tEPSS_score: {'✅' if epss_score else '❌'}")
        print(f"\tEPSS_percentile: {'✅' if epss_percentile else '❌'}")

    return {
        "CVE_id": cve_id,
        "Description": description,
        "CVSS_score": cvss_score,
        "Base_severity": base_severity,
        "CWE": cwes,
        "Affected_products": affected_products,
        "EPSS_score": epss_score,
        "EPSS_percentile": epss_percentile
    }

# Génération d'un set de CVE uniques
set_cve_uniques = set()

cve_list = df_flux_rss["CVE"]
for cve_list in df_flux_rss["CVE"]:
    for cve_id in cve_list:
        set_cve_uniques.add(cve_id)

# Exraction des données via les APIs
liste_cve_info = []

for cve_id in set_cve_uniques:
    data = get_api_data(cve_id)
    if data:
        liste_cve_info.append(data)

df_cves = pd.DataFrame(liste_cve_info)

## Etape 4 - Consolidation des Données
df_flux_exploded = df_flux_rss.explode('CVE')  # une ligne par CVE

# Convertir les dictionnaires de 'Affected_products' en DataFrame à part
affected_rows = []

for _, row in df_cves.iterrows():
    cve_id = row['CVE_id']
    products = row['Affected_products']
    for prod in products:
        affected_rows.append({
            'CVE_id': cve_id,
            'vendor': prod.get('vendor'),
            'product': prod.get('product'),
            'version': prod.get('versions', [])
        })

df_products = pd.DataFrame(affected_rows)

# Exploser les DataFrames pour avoir une ligne par trucs
df_prod_exploded = df_products.explode('version')
df_cves_exploded = df_cves.explode('CWE')

# Fusionner df_cves avec les produits détaillés
df_cves_flat = pd.merge(df_cves_exploded.drop(columns=['Affected_products']), df_prod_exploded, on='CVE_id', how='left')

# Fusion finale avec les flux RSS
df_consolidated = pd.merge(
    df_flux_exploded,
    df_cves_flat,
    left_on='CVE',
    right_on='CVE_id',
    how='left'
)

# Réorganiser les colonnes
df_consolidated = df_consolidated[[
    'Id', 'Link', 'Title', 'Type', 'Published', 'Summary',
    'CVE_id', 'Description', 'CVSS_score', 'Base_severity',
    'EPSS_score', 'EPSS_percentile', 'CWE',
    'vendor', 'product', 'version'
]]


# Supprime toutes les entrées où cve_id est NaN
df_consolidated = df_consolidated.dropna(subset=['CVE_id'])


# Convert dataframe to CSV
df_consolidated.to_csv("DataFrame_Complet.csv", index=False, encoding='utf-8-sig')