// /api/uploadFamilyMemberPhoto.js
//
// Family-member variant of uploadMemberPhoto.js (see that file for the
// full explanation of WHY this proxies through service_role instead of
// letting the app upload to Supabase Storage directly -- same platform
// issue, same workaround).
//
// The difference: instead of updating the caller's OWN member row, this
// uploads a photo for one of the caller's family_members rows (see
// "My Family" in the app -- self-service, member-managed). We verify the
// token belongs to a real signed-in member, derive their memberNo
// server-side from their verified email (never trust a client-supplied
// memberNo), then confirm the target familyMemberId actually belongs to
// THAT memberNo before uploading -- so a member can never upload a photo
// onto another member's family list by guessing/tampering with an id.
//
// Reuses the same "member-photos" bucket as member profile photos (no
// new bucket/policy needed) with a distinct "family_" filename prefix so
// the two sets of files stay easy to tell apart if ever inspected
// manually.
//
// Same env vars as uploadMemberPhoto.js: SUPABASE_URL, SUPABASE_ANON_KEY,
// SUPABASE_SERVICE_ROLE_KEY -- already set in this Vercel project, no new
// env vars needed.
//
// NOTE: this endpoint only uploads the file and returns its public URL --
// it does NOT write family_members.photo_url itself. The app does that
// afterwards with its own authenticated PATCH (SupabaseFamilyApi
// .updateFamilyMemberPhoto), which RLS already allows since the caller
// owns that row -- same two-step pattern as the member profile photo flow
// (upload here, then a separate authenticated write of the URL).

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

  const { accessToken, familyMemberId, imageBase64 } = req.body || {};
  if (!accessToken || !familyMemberId || !imageBase64) {
    return res.status(400).json({ error: 'Missing accessToken, familyMemberId, or imageBase64' });
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

  // Step 1b: look up the CALLER's own memberNo server-side, using the
  // verified email -- same as uploadMemberPhoto.js. This is the anchor
  // everything else is checked against.
  let callerMemberNo;
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
    callerMemberNo = rows[0].member_no;
  } catch (e) {
    return res.status(502).json({ error: 'Could not reach Supabase to look up member.', detail: String(e) });
  }

  // Step 1c: confirm the target family_members row actually belongs to
  // the caller. Without this check, a signed-in member could upload a
  // photo onto ANY family_members id, not just their own family list.
  try {
    const familyResp = await fetch(
      `${SUPABASE_URL}/rest/v1/family_members?select=member_no&id=eq.${encodeURIComponent(familyMemberId)}`,
      {
        headers: {
          apikey: SUPABASE_SERVICE_ROLE_KEY,
          Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
        },
      }
    );
    if (!familyResp.ok) {
      return res.status(502).json({ error: 'Could not look up family member record.' });
    }
    const rows = await familyResp.json();
    if (!rows || rows.length === 0) {
      return res.status(404).json({ error: 'Family member not found.' });
    }
    if (rows[0].member_no !== callerMemberNo) {
      return res.status(403).json({ error: 'This family member does not belong to your account.' });
    }
  } catch (e) {
    return res.status(502).json({ error: 'Could not reach Supabase to verify family member ownership.', detail: String(e) });
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
  const safeFamilyMemberId = String(familyMemberId).replace(/[^a-zA-Z0-9_-]/g, '');
  if (!safeFamilyMemberId) {
    return res.status(400).json({ error: 'Invalid familyMemberId.' });
  }
  const fileName = `family_${safeFamilyMemberId}_${Date.now()}.jpg`;

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
