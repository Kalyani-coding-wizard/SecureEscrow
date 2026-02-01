"""
OTP Manager for Email-based One-Time Password Authentication.
Generates, stores, and validates OTPs with 60-second validity.
"""

import random
import time
import sys
import logging
from datetime import datetime
from flask import session, current_app


class OTPManager:
    """Manages OTP generation, storage, and validation."""
    
    OTP_VALIDITY_SECONDS = 60  # OTP valid for 60 seconds (1 minute)
    OTP_LENGTH = 6  # 6-digit OTP
    
    @staticmethod
    def generate_otp() -> str:
        """Generate a 6-digit numeric OTP."""
        return ''.join([str(random.randint(0, 9)) for _ in range(OTPManager.OTP_LENGTH)])
    
    @staticmethod
    def create_and_store_otp(email: str) -> str:
        """
        Generate OTP, store in session, and print to console.
        
        Args:
            email: User's email for display
            
        Returns:
            The generated OTP
        """
        otp = OTPManager.generate_otp()
        timestamp = time.time()
        
        # Store OTP and timestamp in session
        session['otp_code'] = otp
        session['otp_timestamp'] = timestamp
        session['otp_email'] = email
        
        # Print OTP using multiple methods to ensure visibility in Flask debug mode
        otp_message = f"""
================================================================================
                           OTP AUTHENTICATION
--------------------------------------------------------------------------------
                    Email: {email}
                    OTP Code: {otp}
                    Valid for: {OTPManager.OTP_VALIDITY_SECONDS} seconds
                    Generated at: {datetime.now().strftime('%H:%M:%S')}
================================================================================
"""
        # Method 1: Direct write to file descriptors (bypasses werkzeug redirection)
        import os
        try:
            os.write(1, otp_message.encode())  # stdout file descriptor
            os.write(2, otp_message.encode())  # stderr file descriptor
        except OSError:
            pass
        
        # Method 2: Standard print with flush
        print(otp_message, flush=True)
        
        # Method 3: sys.stderr write with flush
        sys.stderr.write(otp_message)
        sys.stderr.flush()
        
        # Method 4: Direct write to sys.__stdout__ (original stdout before any redirection)
        if sys.__stdout__ is not None:
            sys.__stdout__.write(otp_message)
            sys.__stdout__.flush()
        if sys.__stderr__ is not None:
            sys.__stderr__.write(otp_message)
            sys.__stderr__.flush()
        
        # Also use Flask's logger
        try:
            current_app.logger.warning(f"\n{'='*50}")
            current_app.logger.warning(f"  OTP AUTHENTICATION")
            current_app.logger.warning(f"  {email} : {otp}")
            current_app.logger.warning(f"  Valid for {OTPManager.OTP_VALIDITY_SECONDS} seconds")
            current_app.logger.warning(f"{'='*50}")
        except RuntimeError:
            pass  # Outside application context
        
        return otp
    
    @staticmethod
    def verify_otp(submitted_otp: str) -> tuple[bool, str]:
        """
        Verify the submitted OTP against stored OTP.
        
        Args:
            submitted_otp: The OTP entered by user
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        stored_otp = session.get('otp_code')
        otp_timestamp = session.get('otp_timestamp')
        
        if not stored_otp or not otp_timestamp:
            return False, "No OTP found. Please request a new one."
        
        # Check if OTP has expired
        current_time = time.time()
        if current_time - otp_timestamp > OTPManager.OTP_VALIDITY_SECONDS:
            return False, "OTP has expired. Please request a new one."
        
        # Compare OTPs
        if submitted_otp.strip() != stored_otp:
            return False, "Invalid OTP. Please try again."
        
        # Clear OTP from session after successful verification
        OTPManager.clear_otp()
        
        return True, "OTP verified successfully."
    
    @staticmethod
    def can_resend_otp() -> tuple[bool, int]:
        """
        Check if OTP can be resent (after 30 seconds).
        
        Returns:
            Tuple of (can_resend, seconds_remaining)
        """
        otp_timestamp = session.get('otp_timestamp')
        
        if not otp_timestamp:
            return True, 0
        
        elapsed = time.time() - otp_timestamp
        
        if elapsed >= OTPManager.OTP_VALIDITY_SECONDS:
            return True, 0
        
        remaining = int(OTPManager.OTP_VALIDITY_SECONDS - elapsed)
        return False, remaining
    
    @staticmethod
    def clear_otp():
        """Clear OTP data from session."""
        session.pop('otp_code', None)
        session.pop('otp_timestamp', None)
        session.pop('otp_email', None)
    
    @staticmethod
    def get_time_remaining() -> int:
        """Get seconds remaining until OTP expires."""
        otp_timestamp = session.get('otp_timestamp')
        
        if not otp_timestamp:
            return 0
        
        elapsed = time.time() - otp_timestamp
        remaining = OTPManager.OTP_VALIDITY_SECONDS - elapsed
        
        return max(0, int(remaining))
