// /api/uploadMemberPhotoAdmin.js
//
// Admin-only variant of uploadMemberPhoto.js (see that file for the full
// explanation of WHY this proxies through service_role instead of letting
// the app upload to Supabase Storage directly -- same platform issue, same
// workaround).
//
// The difference: uploadMemberPhoto.js only lets a member upload their OWN
// photo (it derives memberNo server-side from the caller's own email, so
// one member can never overwrite another's photo). This endpoint is for
// an ADMIN bulk-uploading photos on behalf of OTHER members (e.g. from
// WhatsApp-collected photos named by member_no) -- so it accepts a target
// memberNo from the request body, but ONLY after confirming the calling
// account is a real signed-in member with is_admin = true in the members
// table. A non-admin token is rejected outright.
//
// Same env vars as uploadMemberPhoto.js: SUPABASE_URL, SUPABASE_ANON_KEY,
// SUPABASE_SERVICE_ROLE_KEY -- already set in this Vercel project, no new
// env vars needed.

export const config = {
  api: {
    bodyParser: { sizeLimit: '4mb' },
  },
};

const PHOTO_BUCKET = 'member-photos';
const MAX_IMAGE_BYTES = 2 * 1024 * 1024; // 2 MB safety cap

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { accessToken, memberNo, imageBase64 } = req.body || {};
  if (!accessToken || !memberNo || !imageBase64) {
    return res.status(400).json({ error: 'Missing accessToken, memberNo, or imageBase64' });
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
  // This is the only thing that makes it safe to accept a client-supplied
  // memberNo below -- without this check, any signed-in member could
  // overwrite any other member's photo.
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

  // Step 2: decode + size-check the image.
  let buffer;
  try {
    buffer = Buffer.from(imageBase64, 'base64');
  } catch (e) {
    return res.status(400).json({ error: 'imageBase64 is not valid base64.' });
  }
  if (buffer.length === 0) {
    return res.status(400).json({ error: 'Empty image.' });
  }
  if (buffer.length > MAX_IMAGE_BYTES) {
    return res.status(413).json({ error: 'Image too large.' });
  }

  // Step 3: upload with the service_role key, to the ADMIN-SUPPLIED
  // memberNo (safe now that we've confirmed the caller is an admin).
  const safeMemberNo = String(memberNo).replace(/[^a-zA-Z0-9_-]/g, '');
  if (!safeMemberNo) {
    return res.status(400).json({ error: 'Invalid memberNo.' });
  }
  const fileName = `${safeMemberNo}_${Date.now()}.jpg`;

  try {
    const uploadResp = await fetch(
      `${SUPABASE_URL}/storage/v1/object/${PHOTO_BUCKET}/${fileName}`,
      {
        method: 'POST',
        headers: {
          apikey: SUPABASE_SERVICE_ROLE_KEY,
          Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
          'Content-Type': 'image/jpeg',
          'x-upsert': 'true',
        },
        body: buffer,
      }
    );

    if (!uploadResp.ok) {
      const detail = await uploadResp.text();
      return res.status(502).json({ error: 'Supabase Storage upload failed.', detail });
    }
  } catch (e) {
    return res.status(502).json({ error: 'Could not reach Supabase Storage.', detail: String(e) });
  }

  const publicUrl = `${SUPABASE_URL}/storage/v1/object/public/${PHOTO_BUCKET}/${fileName}`;
  return res.status(200).json({ url: publicUrl });
}
