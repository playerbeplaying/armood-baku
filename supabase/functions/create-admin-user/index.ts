// supabase/functions/delete-admin-user/index.ts
//
// Deploy with: supabase functions deploy delete-admin-user
//
// Called by removeStaff() in admin.html.
// Deletes the user from both the admins table AND Supabase Auth,
// fully revoking all access including active sessions.

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    // ── 1. Verify caller is an authenticated director ──
    const authHeader = req.headers.get('Authorization')
    if (!authHeader) {
      return new Response(JSON.stringify({ error: 'Missing Authorization header' }), {
        status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      })
    }

    const anonClient = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SUPABASE_ANON_KEY')!,
    )

    const { data: { user }, error: userErr } = await anonClient.auth.getUser(
      authHeader.replace('Bearer ', '')
    )
    if (userErr || !user) {
      return new Response(JSON.stringify({ error: 'Invalid token' }), {
        status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      })
    }

    // Check caller is a director
    const { data: adminRow } = await anonClient
      .from('admins')
      .select('role')
      .eq('id', user.id)
      .single()

    if (!adminRow || adminRow.role !== 'director') {
      return new Response(JSON.stringify({ error: 'Forbidden: directors only' }), {
        status: 403, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      })
    }

    // ── 2. Get the target user id from request ──
    const { userId } = await req.json()
    if (!userId) {
      return new Response(JSON.stringify({ error: 'Missing userId' }), {
        status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      })
    }

    // Prevent self-deletion
    if (userId === user.id) {
      return new Response(JSON.stringify({ error: 'Cannot remove yourself' }), {
        status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      })
    }

    const adminClient = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
    )

    // ── 3. Delete from admins table first ──
    const { error: deleteAdminErr } = await adminClient
      .from('admins')
      .delete()
      .eq('id', userId)

    if (deleteAdminErr) {
      return new Response(JSON.stringify({ error: 'Failed to remove admin record' }), {
        status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      })
    }

    // ── 4. Delete from Supabase Auth — fully revokes all sessions ──
    const { error: deleteAuthErr } = await adminClient.auth.admin.deleteUser(userId)

    if (deleteAuthErr) {
      return new Response(JSON.stringify({ error: 'Admin record removed but auth deletion failed: ' + deleteAuthErr.message }), {
        status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      })
    }

    return new Response(JSON.stringify({ success: true }), {
      status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    })

  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    })
  }
})
