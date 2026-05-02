import os
import sys
import uvicorn
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

old_ip_folder = os.path.join(current_dir, "IP Address")
new_ip_folder = os.path.join(current_dir, "IP_Address")
if os.path.exists(old_ip_folder) and not os.path.exists(new_ip_folder):
    os.rename(old_ip_folder, new_ip_folder)

from Email import check_email 
from IP_Address import IP_check 
from Phone import check_phone 

app = FastAPI(title="Multi-Vector Analysis Platform")

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Frontend Routes
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request=request, name="email.html")

@app.get("/email", response_class=HTMLResponse)
async def email_page(request: Request):
    return templates.TemplateResponse(request=request, name="email.html")

@app.get("/ip", response_class=HTMLResponse)
async def ip_page(request: Request):
    return templates.TemplateResponse(request=request, name="ip.html")

@app.get("/phone", response_class=HTMLResponse)
async def phone_page(request: Request):
    return templates.TemplateResponse(request=request, name="phone.html")

# API Analysis Routes
@app.post("/api/analyze/email")
async def analyze_email(email: str = Form(...)):
    return check_email.evaluate_email(email)

@app.post("/api/analyze/ip")
async def analyze_ip(ip: str = Form(...)):
    return IP_check.evaluate_ip(ip)

@app.post("/api/analyze/phone")
async def analyze_phone(phone: str = Form(...)):
    return check_phone.check_phone_number(phone)

@app.get("/url", response_class=HTMLResponse)
async def url_page(request: Request):
    return templates.TemplateResponse(request=request, name="url.html")

@app.post("/api/analyze/url")
async def analyze_url(url: str = Form(...)):
    return {"status": "success", "received_url": url, "message": "Pending backend integration"}

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8080, reload=True)
