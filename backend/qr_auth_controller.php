<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\DB;

class QrAuthController extends Controller
{
    private $secretKey = "DYNAMIC_QR_SECRET_KEY_2026";
    private $validityWindow = 30; // seconds

    /**
     * Generates a dynamic QR Code token for the current user session.
     */
    public function generateQrToken(Request $request)
    {
        $userId = $request->user()->id;
        $timeBlock = floor(time() / $this->validityWindow);
        $payload = "USER:{$userId}:BLOCK:{$timeBlock}";
        
        $hmac = hash_hmac('sha256', $payload, $this->secretKey);
        $qrToken = base64_encode("{$payload}:{$hmac}");

        return response()->json([
            'status' => 'success',
            'qr_token' => $qrToken,
            'expires_in_seconds' => $this->validityWindow - (time() % $this->validityWindow)
        ]);
    }

    /**
     * Verifies scanned QR token against replay attacks and records attendance.
     */
    public function verifyAttendance(Request $request)
    {
        $request->validate([
            'qr_token' => 'required|string',
            'session_id' => 'required|integer'
        ]);

        $decoded = base64_decode($request->input('qr_token'));
        $parts = explode(':', $decoded);

        if (count($parts) !== 5) {
            return response()->json(['error' => 'Invalid QR token format'], 400);
        }

        $userId = intval($parts[1]);
        $timeBlock = intval($parts[3]);
        $receivedHmac = $parts[4];

        $currentTimeBlock = floor(time() / $this->validityWindow);

        // Anti-Replay check: max 1 window skew
        if (abs($currentTimeBlock - $timeBlock) > 1) {
            return response()->json(['error' => 'Replay attack detected or token expired'], 403);
        }

        $expectedPayload = "USER:{$userId}:BLOCK:{$timeBlock}";
        $expectedHmac = hash_hmac('sha256', $expectedPayload, $this->secretKey);

        if (!hash_equals($expectedHmac, $receivedHmac)) {
            return response()->json(['error' => 'HMAC signature verification failed'], 401);
        }

        // Prevent Duplicate Attendance using PDO prepared query
        $alreadyRecorded = DB::select(
            "SELECT id FROM attendance_records WHERE user_id = ? AND session_id = ?",
            [$userId, $request->input('session_id')]
        );

        if (!empty($alreadyRecorded)) {
            return response()->json(['message' => 'Attendance already recorded'], 200);
        }

        DB::insert(
            "INSERT INTO attendance_records (user_id, session_id, scanned_at) VALUES (?, ?, NOW())",
            [$userId, $request->input('session_id')]
        );

        return response()->json(['status' => 'success', 'message' => 'Attendance verified successfully']);
    }
}
