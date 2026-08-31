// /api/storageUsage.js
//
// Admin-only: reports Supabase Storage usage for THIS project
// (karayogam-photos, where sangham-photo-proxy actually stores photos --
// see uploadMemberPhoto.js / uploadMemberPhotoAdmin.js in this same repo).
//
// WHY THIS EXISTS:
// The Android app's own in-app "Check Storage Usage" panel only has
// SUPABASE_URL/SUPABASE_ANON_KEY for the MAIN app-data Supabase project
// (members, services, bank transactions, etc). It has no credentials for
// THIS separate photo-storage project, so it always reports "no buckets
// found" here -- correctly, but unhelpfully, since this is where photos
// actually live. This endpoint lets the app ask THIS proxy (which already
// holds this project's service_role key, same as the upload endpoints)
// for the real numbers, without ever shipping that key into the APK.
//
// Auth pattern is identical to uploadMemberPhotoAdmin.js: verify the
// caller's accessToken is a real signed-in member, then confirm
// is_admin = true for them, before revealing anything. A non-admin
// (or a stranger with no token at all) gets a 401/403, not usage data.
//
// Same env vars as the other endpoints in this repo: SUPABASE_URL,
// SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY -- already set in this
// Vercel project, no new env vars needed.

export const config = {
  api: {
    bodyParser: { sizeLimit: '1mb' },
  },
};

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { accessToken } = req.body || {};
  if (!accessToken) {
    return res.status(400).json({ error: 'Missing accessToken' });
  }

  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
  const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !SUPABASE_SERVICE_ROLE_KEY) {
    return res.status(500).json({ error: 'Server not configured (missing Supabase env vars)' });
  }

  // Step 1: verify this is a real, currently signed-in member -- not a
  // stranger calling this endpoint directly with a made-up token.
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

  // Step 1b: confirm the CALLER is an admin. Storage usage isn't as
  // sensitive as overwriting someone's photo, but there's no reason to
  // expose it to non-admins either -- same bar as the rest of the Admin
  // Moderation Panel this feeds into.
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

  // Step 2: list every bucket in this project, using the service_role
  // key (which sees everything, unlike an anon key which -- in the
  // Android app's own equivalent check against the OTHER project --
  // only sees public buckets).
  let bucketNames;
  try {
    const bucketResp = await fetch(`${SUPABASE_URL}/storage/v1/bucket`, {
      headers: {
        apikey: SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      },
    });
    if (!bucketResp.ok) {
      const detail = await bucketResp.text();
      return res.status(502).json({ error: 'Could not list buckets.', detail });
    }
    const buckets = await bucketResp.json();
    bucketNames = (buckets || [])
      .map((b) => b?.name)
      .filter((n) => typeof n === 'string' && n.length > 0);
  } catch (e) {
    return res.status(502).json({ error: 'Could not reach Supabase Storage to list buckets.', detail: String(e) });
  }

  if (bucketNames.length === 0) {
    return res.status(200).json({ buckets: [], totalBytes: 0 });
  }

  // Step 3: recursively sum file sizes inside each bucket. Supabase's
  // list endpoint only returns one folder level at a time (subfolders
  // come back with a null "id"), so this walks into every subfolder
  // found -- same recursion the app's own SupabaseStorageApi.kt uses
  // for the main project, kept consistent so the two numbers are
  // computed the same way.
  async function sumBucketBytes(bucketName, prefix = '') {
    const listResp = await fetch(
      `${SUPABASE_URL}/storage/v1/object/list/${bucketName}`,
      {
        method: 'POST',
        headers: {
          apikey: SUPABASE_SERVICE_ROLE_KEY,
          Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ prefix, limit: 1000 }),
      }
    );
    if (!listResp.ok) {
      throw new Error(`HTTP ${listResp.status}`);
    }
    const items = await listResp.json();

    let fileCount = 0;
    let totalBytes = 0;

    for (const item of items) {
      const itemPath = prefix ? `${prefix}/${item.name}` : item.name;
      if (item.id === null || item.id === undefined) {
        // Folder -- recurse into it.
        const sub = await sumBucketBytes(bucketName, itemPath);
        fileCount += sub.fileCount;
        totalBytes += sub.totalBytes;
      } else {
        fileCount += 1;
        totalBytes += item.metadata?.size || 0;
      }
    }

    return { fileCount, totalBytes };
  }

  const bucketResults = [];
  for (const bucketName of bucketNames) {
    try {
      const { fileCount, totalBytes } = await sumBucketBytes(bucketName);
      bucketResults.push({ bucketName, fileCount, totalBytes });
    } catch (e) {
      bucketResults.push({ bucketName, fileCount: 0, totalBytes: 0, error: e.message || 'Failed to read bucket' });
    }
  }

  const totalBytes = bucketResults.reduce((sum, b) => sum + b.totalBytes, 0);
  return res.status(200).json({ buckets: bucketResults, totalBytes });
}
