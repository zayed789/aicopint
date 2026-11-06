"""
Image Metadata Intelligence Service
Handles image metadata extraction using PIL/Pillow (no external dependencies).
Based on exif.py by David Bombal - https://github.com/davidbombal/red-python-scripts
"""

import os
import io
from PIL import Image
from PIL.ExifTags import GPSTAGS, TAGS
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field

logger = __import__('logging').getLogger(__name__)


@dataclass
class GPSCoordinates:
    """Represents GPS coordinates with conversion utilities."""
    latitude: float
    longitude: float
    altitude: Optional[float] = None
    
    def to_decimal(self) -> tuple:
        """Return decimal coordinates."""
        return (self.latitude, self.longitude)
    
    def to_google_maps_url(self) -> str:
        """Generate Google Maps URL."""
        return f"https://maps.google.com/?q={self.latitude},{self.longitude}"
    
    def is_valid(self) -> bool:
        """Check if coordinates are valid."""
        return -90 <= self.latitude <= 90 and -180 <= self.longitude <= 180


@dataclass
class DeviceInfo:
    """Device and camera information."""
    make: Optional[str] = None
    model: Optional[str] = None
    camera_model: Optional[str] = None
    lens_info: Optional[str] = None
    software: Optional[str] = None
    firmware: Optional[str] = None


@dataclass
class TimestampInfo:
    """Temporal metadata."""
    date_taken: Optional[str] = None
    time_taken: Optional[str] = None
    timezone: Optional[str] = None
    date_modified: Optional[str] = None
    date_created: Optional[str] = None


@dataclass
class FileInfo:
    """File metadata."""
    filename: str = ""
    file_size: str = ""
    mime_type: str = ""
    image_width: int = 0
    image_height: int = 0
    resolution: str = ""
    file_format: str = ""


@dataclass
class MetadataStatus:
    """Metadata preservation status."""
    has_exif: bool = False
    has_gps: bool = False
    has_thumbnail: bool = False
    is_stripped: bool = False
    partially_stripped: bool = False


@dataclass
class ImageMetadata:
    """Complete image metadata container."""
    file_info: FileInfo = field(default_factory=FileInfo)
    device_info: DeviceInfo = field(default_factory=DeviceInfo)
    timestamps: TimestampInfo = field(default_factory=TimestampInfo)
    gps: Optional[GPSCoordinates] = None
    status: MetadataStatus = field(default_factory=MetadataStatus)
    raw_metadata: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)


class ImageMetadataService:
    """
    Service for extracting and parsing image metadata using PIL/Pillow.
    Based on exif.py by David Bombal - pure Python implementation, no external dependencies.
    """
    
    # Supported image formats (PIL supported)
    SUPPORTED_FORMATS = {'.jpg', '.jpeg', '.png', '.webp', '.tiff', '.tif', '.bmp', '.gif'}
    
    # MIME type mappings
    MIME_TYPES = {
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.png': 'image/png',
        '.webp': 'image/webp',
        '.tiff': 'image/tiff',
        '.tif': 'image/tiff',
        '.bmp': 'image/bmp',
        '.gif': 'image/gif'
    }
    
    def validate_image(self, file_path: str) -> tuple[bool, str]:
        """Validate image file before processing."""
        if not os.path.exists(file_path):
            return False, "File not found"
        
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in self.SUPPORTED_FORMATS:
            return False, f"Unsupported format: {ext}. Supported: {', '.join(self.SUPPORTED_FORMATS)}"
        
        # Check file size (max 50MB)
        max_size = 50 * 1024 * 1024
        file_size = os.path.getsize(file_path)
        if file_size > max_size:
            return False, f"File too large: {file_size / (1024*1024):.1f}MB (max 50MB)"
        
        if file_size == 0:
            return False, "File is empty"
        
        return True, ""
    
    def is_available(self) -> bool:
        """Check if PIL is available (always True if installed)."""
        try:
            from PIL import Image
            return True
        except ImportError:
            return False
    
    @staticmethod
    def convert_decimal_degrees(degree: float, minutes: float, seconds: float, direction: str) -> float:
        """Convert GPS coordinates from degrees/minutes/seconds to decimal degrees."""
        decimal_degrees = degree + minutes / 60 + seconds / 3600
        if direction == "S" or direction == "W":
            decimal_degrees *= -1
        return decimal_degrees
    
    def create_google_maps_url(self, gps_coords: dict) -> str:
        """Generate Google Maps URL from GPS coordinates."""
        dec_deg_lat = self.convert_decimal_degrees(
            float(gps_coords["lat"][0]),
            float(gps_coords["lat"][1]),
            float(gps_coords["lat"][2]),
            gps_coords["lat_ref"]
        )
        dec_deg_lon = self.convert_decimal_degrees(
            float(gps_coords["lon"][0]),
            float(gps_coords["lon"][1]),
            float(gps_coords["lon"][2]),
            gps_coords["lon_ref"]
        )
        return f"https://maps.google.com/?q={dec_deg_lat},{dec_deg_lon}"
    
    def extract_metadata(self, image_path: str) -> ImageMetadata:
        """
        Extract comprehensive metadata from image using PIL/Pillow.
        
        Args:
            image_path: Path to image file
            
        Returns:
            ImageMetadata object with parsed information
        """
        metadata = ImageMetadata()
        
        # Validate first
        is_valid, error = self.validate_image(image_path)
        if not is_valid:
            metadata.warnings.append(error)
            return metadata
        
        try:
            # Open image with PIL
            with Image.open(image_path) as img:
                # Basic file info
                metadata.file_info.filename = os.path.basename(image_path)
                metadata.file_info.file_format = img.format if img.format else os.path.splitext(image_path)[1].upper().replace('.', '')
                metadata.file_info.image_width = img.width
                metadata.file_info.image_height = img.height
                metadata.file_info.resolution = f"{img.width} x {img.height}"
                
                # File size
                file_size = os.path.getsize(image_path)
                if file_size < 1024 * 1024:
                    metadata.file_info.file_size = f"{file_size / 1024:.1f} KB"
                else:
                    metadata.file_info.file_size = f"{file_size / (1024*1024):.1f} MB"
                
                # MIME type
                ext = os.path.splitext(image_path)[1].lower()
                metadata.file_info.mime_type = self.MIME_TYPES.get(ext, 'unknown')
                
                # Extract EXIF data
                exif_data = img._getexif()
                
                if exif_data is None:
                    metadata.warnings.append("No EXIF data found in this image. Metadata may have been stripped.")
                    metadata.status.is_stripped = True
                    return metadata
                
                # Parse EXIF tags
                gps_coords = {}
                
                for tag_id, value in exif_data.items():
                    tag_name = TAGS.get(tag_id, tag_id)
                    
                    # GPS Info
                    if tag_name == "GPSInfo":
                        for key, val in value.items():
                            gps_tag = GPSTAGS.get(key, key)
                            
                            if gps_tag == "GPSLatitude":
                                gps_coords["lat"] = val
                            elif gps_tag == "GPSLongitude":
                                gps_coords["lon"] = val
                            elif gps_tag == "GPSLatitudeRef":
                                gps_coords["lat_ref"] = val
                            elif gps_tag == "GPSLongitudeRef":
                                gps_coords["lon_ref"] = val
                            elif gps_tag == "GPSAltitude":
                                try:
                                    metadata.gps = metadata.gps or GPSCoordinates(0, 0)
                                    metadata.gps.altitude = float(val) if isinstance(val, (int, float)) else None
                                except:
                                    pass
                    
                    # Device Info
                    elif tag_name == "Make":
                        metadata.device_info.make = str(value) if value else None
                    elif tag_name == "Model":
                        metadata.device_info.model = str(value) if value else None
                        metadata.device_info.camera_model = str(value) if value else None
                    elif tag_name == "LensModel":
                        metadata.device_info.lens_info = str(value) if value else None
                    elif tag_name == "Software":
                        metadata.device_info.software = str(value) if value else None
                    
                    # Timestamps
                    elif tag_name == "DateTimeOriginal":
                        try:
                            dt_str = str(value)
                            if len(dt_str) >= 19:
                                metadata.timestamps.date_taken = f"{dt_str[0:4]}-{dt_str[5:7]}-{dt_str[8:10]}"
                                metadata.timestamps.time_taken = f"{dt_str[11:13]}:{dt_str[14:16]}:{dt_str[17:19]}"
                        except:
                            metadata.timestamps.date_taken = str(value)
                    elif tag_name == "DateTime":
                        metadata.timestamps.date_modified = str(value)
                    elif tag_name == "OffsetTime":
                        metadata.timestamps.timezone = str(value)
                
                # Process GPS coordinates
                if gps_coords and "lat" in gps_coords and "lon" in gps_coords:
                    try:
                        lat = self.convert_decimal_degrees(
                            float(gps_coords["lat"][0]),
                            float(gps_coords["lat"][1]),
                            float(gps_coords["lat"][2]),
                            gps_coords["lat_ref"]
                        )
                        lon = self.convert_decimal_degrees(
                            float(gps_coords["lon"][0]),
                            float(gps_coords["lon"][1]),
                            float(gps_coords["lon"][2]),
                            gps_coords["lon_ref"]
                        )
                        metadata.gps = GPSCoordinates(latitude=lat, longitude=lon)
                    except (ValueError, TypeError, KeyError, IndexError) as e:
                        logger.warning(f"Could not parse GPS coordinates: {e}")
                
                # Determine metadata status
                metadata.status.has_exif = True
                metadata.status.has_gps = metadata.gps is not None
                
        except Exception as e:
            metadata.warnings.append(f"Error extracting metadata: {str(e)}")
        
        return metadata


# Singleton instance
_image_metadata_service = None


def get_image_metadata_service() -> ImageMetadataService:
    """Get or create singleton instance of ImageMetadataService."""
    global _image_metadata_service
    if _image_metadata_service is None:
        _image_metadata_service = ImageMetadataService()
    return _image_metadata_service
