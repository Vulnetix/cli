import {
    AuthResult,
    Client,
    ensureStrReqBody,
    hexStringToUint8Array,
    isJSON,
    unauthenticatedRoutes,
} from "@/utils";
import { PrismaD1 } from '@prisma/adapter-d1';
import { PrismaClient } from '@prisma/client';

export const errorHandling = async context => {
    const {
        request, // same as existing Worker API
        env, // same as existing Worker API
        params, // if filename includes [id] or [[path]]
        waitUntil, // same as ctx.waitUntil in existing Worker API
        next, // used for middleware or to fetch assets
        data, // arbitrary space for passing data between middlewares
    } = context
    try {
        return await next()
    } catch (err) {
        console.error(err.message, err.stack)
        return new Response(err.message, { status: 500 })
    }
}

// Respond to OPTIONS method
export const onRequestOptions = async () => {
    return new Response(null, {
        status: 204,
        headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Max-Age': '86400',
        },
    })
}

export const setup = async context => {
    const { request, env, data, next } = context
    const adapter = new PrismaD1(env.d1db)
    const { searchParams } = new URL(request.url)
    data.searchParams = searchParams
    if (["POST", "PUT", "DELETE", "PATCH"].includes(request.method.toUpperCase())) {
        data.body = await ensureStrReqBody(request)
        if (isJSON(data.body)) {
            data.json = JSON.parse(data.body)
        }
    }
    const clientOptions = {
        adapter,
        transactionOptions: {
            maxWait: 1500, // default: 2000
            timeout: 2000, // default: 5000
        },
    }
    data.logger = () => { }
    if (env.LOGGER === "DEBUG") {
        data.logger = console.log
        clientOptions.log = [
            {
                emit: "event",
                level: "query",
            },
        ]
    }
    data.prisma = new PrismaClient(clientOptions)
    data.prisma.$on("query", async e => {
        data.logger(`${e.query} ${e.params}`)
    })

    return await next()
}

export const authentication = async context => {
    const { request, next, data } = context
    const url = new URL(request.url)
    if (request.cf.botManagement.verifiedBot || request.cf.botManagement.score <= 60) {
        return new Response(JSON.stringify({ ok: false, error: { message: AuthResult.FORBIDDEN } }), { status: 403 })
    }
    const authRequired =
        !unauthenticatedRoutes.static.includes(url.pathname) &&
        !unauthenticatedRoutes.prefixes.map(i => url.pathname.startsWith(i)).includes(true)

    if (!authRequired || !url.pathname.startsWith('/api/')) {
        return await next()
    }
    const method = request.method.toUpperCase()
    const path = url.pathname + url.search
    const body = ['GET', 'DELETE'].includes(method.toUpperCase()) ? '' : await ensureStrReqBody(request)
    // Retrieve signature and timestamp from headers
    const signature = request.headers.get('authorization')?.replace('HMAC ', '')
    const timestampStr = request.headers.get('x-timestamp')
    const kid = request.headers.get('x-vulnetix-kid')

    if (!signature || !timestampStr || !kid) {
        return new Response(JSON.stringify({ ok: false, error: { message: AuthResult.FORBIDDEN } }), { status: 403 })
    }

    // Convert timestamp from string to integer
    const timestamp = parseInt(timestampStr, 10)
    if (isNaN(timestamp)) {
        data.logger('Invalid timestamp format', timestamp)
        return new Response(JSON.stringify({ ok: false, error: { message: AuthResult.FORBIDDEN } }), { status: 403 })
    }
    // Validate timestamp (you may want to add a check to ensure the request isn't too old)
    const currentTimestamp = new Date().getTime()
    if (Math.abs(currentTimestamp - timestamp) > 3e+5) { // e.g., allow a 5-minute skew
        data.logger('expired, skew', timestamp)
        return new Response(JSON.stringify({ ok: false, error: { message: AuthResult.EXPIRED } }), { status: 401 })
    }
    // Retrieve the session key from the database using Prisma
    const session = await data.prisma.Session.findFirstOrThrow({
        where: { kid }
    })
    if (!session.expiry || session.expiry <= new Date().getTime()) {
        data.logger('expired', timestamp)
        return new Response(JSON.stringify({ ok: false, error: { message: AuthResult.EXPIRED } }), { status: 401 })
    }
    const secretKeyBytes = new TextEncoder().encode(session.secret)
    const payloadBytes = Client.makePayload({
        method,
        path,
        kid,
        timestamp,
        body: encodeURIComponent(body)
    })
    const key = await crypto.subtle.importKey(
        "raw",
        secretKeyBytes,
        { name: "HMAC", hash: "SHA-512" },
        false,
        ["verify"]
    )

    const signatureBytes = hexStringToUint8Array(signature)
    const isValid = await crypto.subtle.verify("HMAC", key, signatureBytes, payloadBytes)

    if (!isValid) {
        data.logger('Invalid signature', signature)
        return new Response(JSON.stringify({ ok: false, error: { message: AuthResult.FORBIDDEN } }), { status: 401 })
    }
    data.session = session

    return await next()
}

// Set CORS to all /api responses
const dynamicHeaders = async context => {
    const {
        request, // same as existing Worker API
        env, // same as existing Worker API
        params, // if filename includes [id] or [[path]]
        waitUntil, // same as ctx.waitUntil in existing Worker API
        next, // used for middleware or to fetch assets
        data, // arbitrary space for passing data between middlewares
    } = context
    const response = await next()
    response.headers.set('Access-Control-Allow-Origin', '*')
    response.headers.set('Access-Control-Max-Age', '86400')
    return response
}

export const onRequest = [errorHandling, setup, authentication, dynamicHeaders]
