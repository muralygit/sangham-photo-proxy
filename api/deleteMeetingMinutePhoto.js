// /api/deleteMeetingMinutePhoto.js
//
// Admin-only photo delete for the Meeting Minutes feature, mirroring
// uploadMeetingMinutePhoto.js's auth pattern (service_role key,
// server-side admin check) -- same reason: direct-from-device Storage
// writes using the signed-in admin's own JWT were failing with a
// row-level security error, so deletes go through this proxy too
// rather than risk the same failure (silently) leaving orphaned files.
//
// Same env vars already set in this Vercel project: SUPABASE_URL,
// SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY -- no new env vars needed.

export const config = {
  api: {
    bodyParser: { sizeLimit: '1mb' },
  },
};

const PHOTO_BUCKET = 'meeting-minutes';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { accessToken, clientId } = req.body || {};
  if (!accessToken || !clientId) {
    return res.status(400).json({ error: 'Missing accessToken or clientId' });
  }

  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
  const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !SUPABASE_SERVICE_ROLE_KEY) {
    return res.status(500).json({ error: 'Server not configured (missing Supabase env vars)' });
  }

  // Step 1: verify this is a real, currently signed-in member.
  let verifiedEmail;
  try {
    const userResp = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
      headers: {
        apikey: SUPABASE_ANON_KEY,
        Authorization: `Bearer ${accessToken}`,
      },
    });
    if (!userResp.ok) {
      return res.status(401).json({ error: 'Invalid or expired session. Please sign in again.' });
    }
    const user = await userResp.json();
    verifiedEmail = user?.email;
    if (!verifiedEmail) {
      return res.status(401).json({ error: 'Could not verify session.' });
    }
  } catch (e) {
    return res.status(502).json({ error: 'Could not reach Supabase Auth to verify session.' });
  }

  // Step 1b: confirm the CALLER (by their own verified email) is an admin.
  try {
    const callerResp = await fetch(
      `${SUPABASE_URL}/rest/v1/members?select=is_admin&email=eq.${encodeURIComponent(verifiedEmail)}`,
      {
        headers: {
          apikey: SUPABASE_SERVICE_ROLE_KEY,
          Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
        },
      }
    );
    if (!callerResp.ok) {
      return res.status(502).json({ error: 'Could not verify admin status.' });
    }
    const rows = await callerResp.json();
    const isAdmin = rows && rows.length > 0 && rows[0].is_admin === true;
    if (!isAdmin) {
      return res.status(403).json({ error: 'Admin access required.' });
    }
  } catch (e) {
    return res.status(502).json({ error: 'Could not reach Supabase to verify admin status.', detail: String(e) });
  }

  // Step 2: delete with the service_role key. clientId is sanitized the
  // same way uploadMeetingMinutePhoto builds the filename, so this only
  // ever targets that admin-owned meeting-minutes object.
  const safeClientId = String(clientId).replace(/[^a-zA-Z0-9_-]/g, '');
  if (!safeClientId) {
    return res.status(400).json({ error: 'Invalid clientId.' });
  }
  const fileName = `${safeClientId}.jpg`;

  try {
    const deleteResp = await fetch(
      `${SUPABASE_URL}/storage/v1/object/${PHOTO_BUCKET}/${fileName}`,
      {
        method: 'DELETE',
        headers: {
          apikey: SUPABASE_SERVICE_ROLE_KEY,
          Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
        },
      }
    );

    // Treat "already gone" as success -- the goal (no orphaned file) is
    // already met, so don't make the caller treat this as an error.
    if (!deleteResp.ok && deleteResp.status !== 404) {
      const detail = await deleteResp.text();
      return res.status(502).json({ error: 'Supabase Storage delete failed.', detail });
    }
  } catch (e) {
    return res.status(502).json({ error: 'Could not reach Supabase Storage.', detail: String(e) });
  }

  return res.status(200).json({ deleted: true });
}
