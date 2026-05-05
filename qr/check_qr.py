import cv2
import numpy as np
from pyzbar.pyzbar import decode

def attempt_decode(image):
    """Attempt to decode QR using pyzbar, fallback to OpenCV."""
    decoded_objects = decode(image)
    for obj in decoded_objects:
        if obj.data:
            return obj.data.decode('utf-8')
    try:
        detector = cv2.QRCodeDetector()
        val, pts, qr_code = detector.detectAndDecode(image)
        if val:
            return val
    except Exception:
        pass
    return None

def extract_qr_payload(contents: bytes) -> dict:
    qr_error_response = {
        "is_safe": False,
        "status": "Please enter a valid qr code",
        "details": ["Unable to detect a code.", "Please provide a clear, valid QR code image."]
    }

    try:
        nparr = np.frombuffer(contents, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

        if img is None:
            return qr_error_response

        # 1. First Pass (Standard)
        payload = attempt_decode(img)
        
        # 2. Second Pass (Grayscale + High Contrast)
        if not payload:
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8,8))
            enhanced = clahe.apply(gray)
            payload = attempt_decode(enhanced)
            
        # 3. Third Pass (Upscaled)
        if not payload:
            resized = cv2.resize(img, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)
            payload = attempt_decode(resized)

        if payload:
            return {
                "success": True, 
                "payload": payload
            }
        
        return qr_error_response

    except Exception as e:
        return {
            "is_safe": False,
            "status": "Error Processing Image",
            "details": [str(e)]
        }