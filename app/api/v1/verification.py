from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Request, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from typing import Optional, Dict, Any
from datetime import datetime, timezone
from threading import Thread
from uuid import uuid4
import tempfile
import os
import shutil
import csv
import io
import filetype
import logging

from app.db.session import get_db, SessionLocal
from app.db.models import Video, Camera, Verification, Segment, VerificationResult, UserRole
from app.core.dependencies import require_analyst
from app.services.verifier import verify_video