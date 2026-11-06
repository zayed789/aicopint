"""
Image Intelligence Routes
Handles image upload, processing, and metadata display.
"""

import os
import uuid
import tempfile
import logging

logger = logging.getLogger(__name__)
from flask import Blueprint, render_template, request, jsonify, session, current_app
from werkzeug.utils import secure_filename
from services.image_metadata_service import get_image_metadata_service, ImageMetadata

# Create blueprint
image_bp = Blueprint('image_intel', __name__, url_prefix='/image-intel')

# Upload configuration
UPLOAD_FOLDER = os.path.join(tempfile.gettempdir(), 'osint_image_uploads')
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'webp', 'tiff', 'tif', 'bmp', 'gif'}
ALLOWED_MIMETYPES = {
    'image/jpeg', 'image/png', 'image/webp',
    'image/tiff', 'image/bmp', 'image/gif'
}

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def _is_authorized():
    """Check if user is logged in."""
    return True


def allowed_file(filename):
    """Check if file extension is allowed."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def validate_mime_type(file_stream):
    """Validate file MIME type by reading header."""
    # Read first few bytes to determine MIME type
    header = file_stream.read(8)
    file_stream.seek(0)
    
    # Magic numbers for common image formats
    magic_numbers = {
        b'\xff\xd8\xff': 'image/jpeg',  # JPEG
        b'\x89PNG\r\n\x1a\n': 'image/png',  # PNG
        b'GIF87a': 'image/gif',  # GIF
        b'GIF89a': 'image/gif',  # GIF
        b'RIFF': 'image/webp',  # WebP (RIFF header)
        b'II*\x00': 'image/tiff',  # TIFF little-endian
        b'MM\x00*': 'image/tiff',  # TIFF big-endian
        b'BM': 'image/bmp',  # BMP
    }
    
    for magic, mime in magic_numbers.items():
        if header.startswith(magic):
            return mime
    
    # HEIC detection (ftyp box)
    if b'ftyp' in header[:8]:
        return 'image/heic'
    
    return None


@image_bp.route('/')
def index():
    """Main Image Intelligence dashboard."""
    if not _is_authorized():
        from flask import redirect, url_for
        return redirect(url_for("login"))
    
    return render_template(
        'image_intel.html',
        police_email=session.get("police_email", ""),
        police_role=session.get("police_role", "")
    )


@image_bp.route('/upload', methods=['POST'])
def upload_image():
    """
    Handle image file upload.
    Validates file and returns upload status.
    """
    if not _is_authorized():
        return jsonify({"error": "Unauthorized"}), 401
    
    # Check if file present
    if 'image' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['image']
    
    # Check if file selected
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    # Validate extension
    if not allowed_file(file.filename):
        return jsonify({
            "error": f"Invalid file type. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
        }), 400
    
    # Validate MIME type
    mime_type = validate_mime_type(file.stream)
    if not mime_type:
        return jsonify({"error": "File type not recognized as valid image"}), 400
    
    if mime_type not in ALLOWED_MIMETYPES:
        return jsonify({"error": f"MIME type not allowed: {mime_type}"}), 400
    
    try:
        # Generate secure filename with UUID
        ext = file.filename.rsplit('.', 1)[1].lower()
        unique_filename = f"{uuid.uuid4().hex}.{ext}"
        filename = secure_filename(unique_filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        
        # Save file
        file.save(filepath)
        
        # Get file size
        file_size = os.path.getsize(filepath)
        
        if file_size > MAX_FILE_SIZE:
            os.remove(filepath)
            return jsonify({"error": "File too large (max 50MB)"}), 400
        
        # Store in session for processing
        session['pending_image'] = {
            'filename': filename,
            'original_name': file.filename,
            'filepath': filepath,
            'mime_type': mime_type,
            'size': file_size
        }

        try:
            from services.activity_logger_service import log_activity
            log_activity(
                user_id=session.get('user_id'),
                username=session.get('police_email', ''),
                full_name=session.get('full_name', ''),
                tool_name='image_intel',
                action_type='upload',
                target_input=file.filename,
                metadata={'mime_type': mime_type,
                          'size_bytes': file_size},
            )
        except Exception:
            pass

        return jsonify({
            "success": True,
            "filename": filename,
            "original_name": file.filename,
            "mime_type": mime_type,
            "size": file_size,
            "size_formatted": f"{file_size / 1024:.1f} KB" if file_size < 1024*1024 else f"{file_size / (1024*1024):.1f} MB"
        })
        
    except Exception as e:
        return jsonify({"error": f"Upload failed: {str(e)}"}), 500


@image_bp.route('/analyze', methods=['POST'])
def analyze_image():
    """
    Process uploaded image and extract metadata.
    """
    if not _is_authorized():
        return jsonify({"error": "Unauthorized"}), 401
    
    # Get pending image from session
    pending = session.get('pending_image')
    if not pending:
        return jsonify({"error": "No image uploaded. Please upload first."}), 400
    
    filepath = pending.get('filepath')
    if not os.path.exists(filepath):
        return jsonify({"error": "Uploaded file not found"}), 404
    
    try:
        # Process with ExifTool
        service = get_image_metadata_service()
        metadata = service.extract_metadata(filepath)
        
        # Convert to JSON-serializable dict
        result = _metadata_to_dict(metadata, pending)
        
        # Keep file alive for lens analysis — store filepath separately in session
        session['last_image_analysis'] = result
        session['_lens_filepath'] = filepath
        session.modified = True

        try:
            from services.activity_logger_service import log_activity
            log_activity(
                user_id=session.get('user_id'),
                username=session.get('police_email', ''),
                full_name=session.get('full_name', ''),
                tool_name='image_intel',
                action_type='analyze',
                target_input=pending.get('original_name', ''),
                metadata={'has_gps': result.get('has_gps', False),
                          'has_exif': result.get('has_exif', False),
                          'status': result.get('status', {}).get('text', '')},
            )
        except Exception:
            pass

        return jsonify({
            "success": True,
            "metadata": result
        })
        
    except Exception as e:
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
        except OSError:
            pass
        session.pop('pending_image', None)
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500


@image_bp.route('/status')
def check_status():
    """Check if PIL is available for image processing."""
    if not _is_authorized():
        return jsonify({"error": "Unauthorized"}), 401
    
    service = get_image_metadata_service()
    is_available = service.is_available()
    
    return jsonify({
        "pil_available": is_available,
        "ready": is_available
    })


def _metadata_to_dict(metadata: ImageMetadata, file_info: dict) -> dict:
    """Convert ImageMetadata to JSON-serializable dictionary."""
    
    # GPS data
    gps_data = None
    if metadata.gps and metadata.gps.is_valid():
        gps_data = {
            "latitude": metadata.gps.latitude,
            "longitude": metadata.gps.longitude,
            "altitude": metadata.gps.altitude,
            "google_maps_url": metadata.gps.to_google_maps_url(),
            "coordinates": f"{metadata.gps.latitude:.6f}, {metadata.gps.longitude:.6f}"
        }
    
    # Device info
    device_data = {
        "make": metadata.device_info.make or "Unknown",
        "model": metadata.device_info.model or "Unknown",
        "camera_model": metadata.device_info.camera_model or "Unknown",
        "lens_info": metadata.device_info.lens_info or None,
        "software": metadata.device_info.software or None,
        "firmware": metadata.device_info.firmware or None
    }
    
    # Timestamps
    timestamps = {
        "date_taken": metadata.timestamps.date_taken or "Unknown",
        "time_taken": metadata.timestamps.time_taken or "Unknown",
        "timezone": metadata.timestamps.timezone or "Unknown",
        "date_modified": metadata.timestamps.date_modified or "Unknown",
        "date_created": metadata.timestamps.date_created or "Unknown"
    }
    
    # File info
    file_data = {
        "filename": file_info.get('original_name', metadata.file_info.filename),
        "stored_filename": file_info.get('filename', ''),
        "file_size": metadata.file_info.file_size or file_info.get('size_formatted', 'Unknown'),
        "mime_type": metadata.file_info.mime_type or file_info.get('mime_type', 'Unknown'),
        "format": metadata.file_info.file_format or "Unknown",
        "resolution": metadata.file_info.resolution or "Unknown",
        "width": metadata.file_info.image_width or 0,
        "height": metadata.file_info.image_height or 0
    }
    
    # Status
    status = _determine_status_text(metadata.status)
    
    return {
        "file": file_data,
        "gps": gps_data,
        "device": device_data,
        "timestamps": timestamps,
        "status": status,
        "warnings": metadata.warnings,
        "has_gps": metadata.status.has_gps,
        "has_exif": metadata.status.has_exif
    }


def _determine_status_text(status) -> dict:
    """Determine metadata status for display."""
    if status.is_stripped:
        return {
            "level": "danger",
            "text": "Metadata Completely Stripped",
            "description": "This image contains minimal or no embedded metadata. It may have been processed to remove EXIF data."
        }
    elif status.partially_stripped:
        return {
            "level": "warning",
            "text": "Metadata Partially Stripped",
            "description": "Some metadata fields are missing. The image may have been partially processed."
        }
    elif status.has_exif:
        return {
            "level": "success",
            "text": "Metadata Available",
            "description": "Full EXIF metadata detected including camera information and timestamps."
        }
    else:
        return {
            "level": "info",
            "text": "Basic Metadata Only",
            "description": "Only basic file information available. No EXIF camera data detected."
        }





@image_bp.route('/download/json')
def download_json():
    """Download last analysis as JSON."""
    if not _is_authorized():
        from flask import redirect, url_for
        return redirect(url_for("login"))

    from flask import Response
    import json

    result = session.get('last_image_analysis')
    if not result:
        return jsonify({"error": "No analysis data available"}), 404

    content = json.dumps(result, indent=2, ensure_ascii=False)

    return Response(
        content,
        mimetype="application/json",
        headers={
            "Content-Disposition": f"attachment; filename=image_metadata_{result.get('file', {}).get('stored_filename', 'analysis')}.json"
        }
    )


@image_bp.route('/download/pdf')
def download_pdf():
    """Download last analysis as a professional PDF report."""
    if not _is_authorized():
        from flask import redirect, url_for
        return redirect(url_for("login"))

    from flask import Response
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from services.pdf_report_service import generate_image_pdf

    result = session.get('last_image_analysis')
    if not result:
        return jsonify({"error": "No analysis data available. Run an image scan first."}), 404

    try:
        pdf_bytes = generate_image_pdf(
            result,
            officer_email=session.get('police_email', ''),
            officer_role=session.get('police_role', ''),
        )
        filename = result.get('file', {}).get('filename', 'image')
        safe_name = filename.replace(' ', '_').replace('/', '_')[:40]

        try:
            from services.activity_logger_service import log_activity
            log_activity(
                user_id=session.get('user_id'),
                username=session.get('police_email', ''),
                full_name=session.get('full_name', ''),
                tool_name='image_intel',
                action_type='export_pdf',
                target_input=filename,
            )
        except Exception:
            pass

        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=image_intel_{safe_name}.pdf"
            }
        )
    except Exception as exc:
        import traceback
        print(f"Image PDF Error: {exc}\n{traceback.format_exc()}")
        return jsonify({"error": f"PDF generation failed: {exc}"}), 500
