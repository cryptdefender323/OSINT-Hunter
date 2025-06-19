#!/usr/bin/env python3

import os
import json
import hashlib
import PyPDF2
import docx
import exifread
from PIL import Image
from rich.console import Console
from datetime import datetime

console = Console()

def get_file_info(filepath):
    try:
        stat = os.stat(filepath)
        return {
            "filename": os.path.basename(filepath),
            "size_bytes": stat.st_size,
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "hash_md5": md5_hash(filepath),
            "hash_sha1": sha1_hash(filepath),
            "type": None
        }
    except Exception as e:
        console.print(f"[red]Error accessing file: {e}[/red]")
        return {"error": str(e)}

def md5_hash(filepath):
    hash_md5 = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def sha1_hash(filepath):
    hash_sha1 = hashlib.sha1()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha1.update(chunk)
    return hash_sha1.hexdigest()

def extract_pdf_data(filepath):
    data = {}
    try:
        with open(filepath, "rb") as f:
            reader = PyPDF2.PdfReader(f)
            if reader.metadata:
                raw_metadata = {k: str(v) for k, v in reader.metadata.items()}
                data["metadata"] = raw_metadata

            text_pages = []
            for page in reader.pages:
                text = page.extract_text()
                if text and len(text.strip()) > 0:
                    text_pages.append(text.strip())

            data["page_count"] = len(reader.pages)
            data["text_all_pages"] = text_pages
    except Exception as e:
        data["pdf_error"] = str(e)
    return data

def extract_docx_data(filepath):
    data = {}
    try:
        doc = docx.Document(filepath)
        props = doc.core_properties
        data.update({
            "author": props.author,
            "created": str(props.created),
            "last_modified_by": props.last_modified_by,
            "modified": str(props.modified),
            "title": props.title,
            "subject": props.subject,
            "category": props.category,
            "comments": props.comments,
            "keywords": props.keywords,
        })
    except Exception as e:
        data["docx_error"] = str(e)
    return data

def extract_image_gps(exif):
    lat_tag = 'GPS GPSLatitude'
    lon_tag = 'GPS GPSLongitude'
    lat_ref_tag = 'GPS GPSLatitudeRef'
    lon_ref_tag = 'GPS GPSLongitudeRef'

    if lat_tag not in exif or lon_tag not in exif:
        return {}

    def convert_to_degrees(val):
        d, m, s = [float(x.num) / float(x.den) for x in val.values]
        return d + (m / 60.0) + (s / 3600.0)

    latitude = convert_to_degrees(exif[lat_tag])
    longitude = convert_to_degrees(exif[lon_tag])

    if str(exif.get(lat_ref_tag)) == 'S':
        latitude = -latitude
    if str(exif.get(lon_ref_tag)) == 'W':
        longitude = -longitude

    return {
        "latitude": latitude,
        "longitude": longitude,
        "google_maps": f"https://maps.google.com/?q={latitude},{longitude}"
    }

def extract_image_exif(filepath):
    exif_data = {}
    gps_data = {}

    try:
        with open(filepath, 'rb') as f:
            tags = exifread.process_file(f)

        for tag in tags:
            value = str(tags[tag])
            exif_data[str(tag)] = value

            if "GPS" in str(tag):
                gps_data[str(tag)] = value

        if 'GPS GPSLatitude' in gps_data and 'GPS GPSLongitude' in gps_data:
            gps_coords = extract_image_gps(tags)
            exif_data['GPS Coordinates'] = gps_coords

    except Exception as e:
        exif_data["exif_error"] = str(e)

    return exif_data

def extract_full_text_from_pdf(filepath):
    full_text = []
    try:
        with open(filepath, "rb") as f:
            reader = PyPDF2.PdfReader(f)
            for page in reader.pages:
                text = page.extract_text()
                if text:
                    full_text.append(text.strip())
    except:
        return []

    return full_text

def extract_sensitive_info(text_list):
    KEYWORDS = ["password", "apikey", "secret", "token", "bearer", "login", "email", "nomor hp", "telepon", "rekening", "KTP", "SIM"]
    found = []

    for idx, text in enumerate(text_list):
        matches = [kw for kw in KEYWORDS if kw.lower() in text.lower()]
        if matches:
            found.append({
                "page": idx+1,
                "matches": list(set(matches)),
                "snippet": text[:200] + "..."
            })

    return found

def extract_metadata(filepath):
    ext = os.path.splitext(filepath)[-1].lower()
    file_info = get_file_info(filepath)

    if not file_info or "error" in file_info:
        return file_info

    if ext == ".pdf":
        file_info["type"] = "PDF"
        pdf_data = extract_pdf_data(filepath)
        full_text = extract_full_text_from_pdf(filepath)
        sensitive = extract_sensitive_info(full_text)
        file_info.update(pdf_data)
        file_info["sensitive_keywords"] = sensitive

    elif ext == ".docx":
        file_info["type"] = "DOCX"
        file_info["data"] = extract_docx_data(filepath)

    elif ext in [".jpg", ".jpeg", ".png"]:
        file_info["type"] = "Image"
        file_info["exif"] = extract_image_exif(filepath)

    else:
        file_info["type"] = "Unsupported"
        file_info["data"] = {"error": "File type not supported"}

    return file_info

def save_json(data, filepath):
    os.makedirs("logs", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d%H%M")
    outname = f"logs/metadata_{os.path.basename(filepath)}_{timestamp}.json"

    with open(outname, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    console.print(f"[green]✔ Metadata & results saved to {outname}[/green]")

def run():
    console.rule("[bold cyan]:: METADATA EXTRACTOR PRO ::[/bold cyan]", align="center")
    console.print("[yellow]Masukkan path file atau drag-and-drop file PDF/DOCX/JPG/PNG...[/yellow]")
    filepath = input("Enter file path: ").strip()

    if not os.path.exists(filepath):
        console.print("[red]❌ File tidak ditemukan![/red]")
        return

    console.print(f"[blue]→ Analyzing file: {filepath}[/blue]")
    result = extract_metadata(filepath)
    console.print(json.dumps(result, indent=2, ensure_ascii=False))
    save_json(result, filepath)
