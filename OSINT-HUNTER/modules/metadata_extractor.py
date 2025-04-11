import os
import json
import hashlib
import PyPDF2
import docx
import exifread
from PIL import Image
from rich.console import Console
from datetime import datetime
from tkinter import filedialog, Tk

console = Console()

def file_info(filepath):
    try:
        stat = os.stat(filepath)
        return {
            "filename": os.path.basename(filepath),
            "size_bytes": stat.st_size,
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "hash_md5": hashlib.md5(open(filepath, 'rb').read()).hexdigest(),
            "hash_sha1": hashlib.sha1(open(filepath, 'rb').read()).hexdigest()
        }
    except Exception as e:
        return {"error": f"File info error: {e}"}

def extract_pdf_metadata(filepath):
    console.print(f"[cyan]→ Extracting PDF metadata & full text[/cyan]")
    metadata = {}
    try:
        with open(filepath, "rb") as f:
            reader = PyPDF2.PdfReader(f)
            meta_raw = reader.metadata or {}
            metadata["metadata"] = {k: str(v) for k, v in meta_raw.items()}
            metadata["page_count"] = len(reader.pages)
            metadata["text_all_pages"] = []

            for page in reader.pages:
                try:
                    text = page.extract_text()
                    if text:
                        metadata["text_all_pages"].append(text.strip())
                except:
                    continue
    except Exception as e:
        console.print(f"[red]PDF error: {e}[/red]")
        metadata["error"] = str(e)
    return metadata

def extract_docx_metadata(filepath):
    console.print(f"[cyan]→ Extracting DOCX metadata[/cyan]")
    data = {}
    try:
        doc = docx.Document(filepath)
        core = doc.core_properties
        data = {
            "author": core.author,
            "created": str(core.created),
            "last_modified_by": core.last_modified_by,
            "modified": str(core.modified),
            "title": core.title,
            "subject": core.subject,
            "category": core.category,
            "comments": core.comments,
            "keywords": core.keywords,
        }
    except Exception as e:
        console.print(f"[red]DOCX error: {e}[/red]")
    return data

def extract_image_exif(filepath):
    console.print(f"[cyan]→ Extracting EXIF from image[/cyan]")
    exif_data = {}
    gps_data = {}

    try:
        with open(filepath, 'rb') as f:
            tags = exifread.process_file(f)

        for tag in tags:
            exif_data[tag] = str(tags[tag])
            if "GPS" in tag:
                gps_data[tag] = tags[tag]

        if 'GPS GPSLatitude' in gps_data and 'GPS GPSLongitude' in gps_data:
            def convert_to_degrees(val):
                d, m, s = [float(x.num)/float(x.den) for x in val.values]
                return d + (m / 60.0) + (s / 3600.0)

            lat = convert_to_degrees(gps_data['GPS GPSLatitude'])
            lon = convert_to_degrees(gps_data['GPS GPSLongitude'])
            if str(gps_data.get('GPS GPSLatitudeRef')) == 'S':
                lat = -lat
            if str(gps_data.get('GPS GPSLongitudeRef')) == 'W':
                lon = -lon

            exif_data['GPS Coordinates'] = {
                "latitude": lat,
                "longitude": lon,
                "google_maps": f"https://maps.google.com/?q={lat},{lon}"
            }
    except Exception as e:
        console.print(f"[red]EXIF error: {e}[/red]")
    return exif_data

def extract_metadata(filepath):
    ext = os.path.splitext(filepath)[-1].lower()
    info = file_info(filepath)

    if ext == ".pdf":
        info["type"] = "PDF"
        info["data"] = extract_pdf_metadata(filepath)
    elif ext == ".docx":
        info["type"] = "DOCX"
        info["data"] = extract_docx_metadata(filepath)
    elif ext in [".jpg", ".jpeg", ".png"]:
        info["type"] = "Image"
        info["data"] = extract_image_exif(filepath)
    else:
        info["type"] = "Unknown"
        info["data"] = {"error": "Unsupported file type"}
    return info

def save_json(data, filepath):
    os.makedirs("logs", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d%H%M")
    outname = f"logs/metadata_{os.path.basename(filepath)}_{timestamp}.json"
    with open(outname, "w") as f:
        json.dump(data, f, indent=2)
    console.print(f"[green]✔ Metadata saved to {outname}[/green]")

def run():
    console.print("\n[bold cyan]:: METADATA EXTRACTOR MODULE[/bold cyan]")
    console.print("[yellow]Pilih file (PDF, DOCX, JPG, PNG)...[/yellow]")
    Tk().withdraw()
    filepath = filedialog.askopenfilename()

    if not filepath:
        console.print("[red]❌ No file selected.[/red]")
        return

    console.print(f"[blue]Selected file:[/blue] {filepath}")
    data = extract_metadata(filepath)
    console.print(json.dumps(data, indent=2))
    save_json(data, filepath)
