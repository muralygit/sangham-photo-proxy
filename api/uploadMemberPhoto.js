// /api/uploadMemberPhoto.js
//
// WHY THIS EXISTS:
// Supabase Storage is currently rejecting uploads made with a regular
// member's "authenticated" role JWT with a false RLS error, even though
// the same JWT works fine for every other Supabase Auth / database call,
// and even though the RLS policy on storage.objects is confirmed correct.
// (Verified via SQL: a raw `set local role authenticated; insert ...`
// succeeds directly in Postgres, and only the Storage REST API rejects
// the equivalent request when it comes from a real end-user JWT. A
// service_role key upload to the same bucket succeeds instantly.)
//
// This endpoint works around that platform issue: the app sends the
// member's access token + their compressed photo here. We verify the
// token is a genuine signed-in member (so this can't be abused by
// strangers), then upload to Supabase Storage using the service_role
// key server-side, which we've confirmed works.
//
// SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY must be set
// as environment variables in the Vercel project settings.
// SUPABASE_SERVICE_ROLE_KEY must NEVER be exposed to the Android app or
// committed to any repo -- it lives only here, in Vercel's env vars.

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

  const { accessToken, imageBase64 } = req.body || {};
  if (!accessToken || !imageBase64) {
    return res.status(400).json({ error: 'Missing accessToken or imageBase64' });
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

  // Step 1b: look up the member's own memberNo server-side, using the
  // verified email -- never trust a memberNo sent by the client, or one
  // member could overwrite another member's photo by editing the request.
  // ADJUST 'email' below if your members table uses a different column
  // (e.g. auth_user_id) to link to Supabase Auth users.
  let memberNo;
  try {
    const memberResp = await fetch(
      `${SUPABASE_URL}/rest/v1/members?select=member_no&email=eq.${encodeURIComponent(verifiedEmail)}`,
      {
        headers: {
          apikey: SUPABASE_SERVICE_ROLE_KEY,
          Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
        },
      }
    );
    if (!memberResp.ok) {
      return res.status(502).json({ error: 'Could not look up member record.' });
    }
    const rows = await memberResp.json();
    if (!rows || rows.length === 0) {
      return res.status(404).json({ error: 'No member record found for this account.' });
    }
    memberNo = rows[0].member_no;
  } catch (e) {
    return res.status(502).json({ error: 'Could not reach Supabase to look up member.', detail: String(e) });
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

  // Step 3: upload with the service_role key, which we've confirmed
  // works reliably against this bucket.
  const safeMemberNo = String(memberNo).replace(/[^a-zA-Z0-9_-]/g, '');
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
