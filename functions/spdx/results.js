import { Server } from "@/utils";
import { PrismaD1 } from '@prisma/adapter-d1';
import { PrismaClient } from '@prisma/client';

export async function onRequestGet(context) {
    const {
        request, // same as existing Worker API
        env, // same as existing Worker API
        params, // if filename includes [id] or [[path]]
        waitUntil, // same as ctx.waitUntil in existing Worker API
        next, // used for middleware or to fetch assets
        data, // arbitrary space for passing data between middlewares
    } = context
    const adapter = new PrismaD1(env.d1db)
    const prisma = new PrismaClient({
        adapter,
        transactionOptions: {
            maxWait: 1500, // default: 2000
            timeout: 2000, // default: 5000
        },
    })
    const verificationResult = await (new Server(request, prisma)).authenticate()
    if (!verificationResult.isValid) {
        return Response.json({ ok: false, result: verificationResult.message })
    }
    const res = await prisma.spdx.findMany({
        where: {
            memberEmail: verificationResult.session.memberEmail,
        },
        omit: {
            memberEmail: true,
        },
        include: {
            repo: true,
        },
        take: 100,
        orderBy: {
            createdAt: 'desc',
        },
    })
    const spdx = res.map(spdxData => {
        spdxData.packages = JSON.parse(spdxData.packagesJSON)
        spdxData.relationships = JSON.parse(spdxData.relationshipsJSON)
        delete spdxData.packagesJSON
        delete spdxData.relationshipsJSON
        return spdxData
    })

    return Response.json({ spdx })
}
