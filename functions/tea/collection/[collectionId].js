import { PrismaD1 } from '@prisma/adapter-d1';
import { PrismaClient } from '@prisma/client';

/**
 * If only the serialNumber parameter is supplied, retrieve the latest version of the BOM from the repository.
 * If providing serialNumber and version, a specific version of the BOM will be retrieved.
 * Supports HTTP content negotiation for all CycloneDX BOM formats and versions.
 * If original is true, returns the original, unmodified BOM.
 * 
 * curl -X GET 'http://localhost:8000/v1/bom?serialNumber=urn%3Auuid%3A3e671687-395b-41f5-a30f-a58921a69b79' -H 'accept: application/vnd.cyclonedx+json; version=1.4'
 */
export async function onRequestGet(context) {
    const {
        request, // same as existing Worker API
        env, // same as existing Worker API
        params, // if filename includes [id] or [[path]]
        waitUntil, // same as ctx.waitUntil in existing Worker API
        next, // used for middleware or to fetch assets
        data, // arbitrary space for passing data between middlewares
    } = context
    try {
        const adapter = new PrismaD1(env.d1db)
        const prisma = new PrismaClient({
            adapter,
            transactionOptions: {
                maxWait: 1500, // default: 2000
                timeout: 2000, // default: 5000
            },
        })
        params.collectionId // id assigned in the system to the specific collection as returned by collection element

        // const member = await prisma.Member.findFirst({
        //     where: {
        //         email: verificationResult.session.memberEmail,
        //     },
        // })
        // return Response.json([]) // [ Collection ]
    } catch (err) {
        console.error(err)
        // return Response.json({ ok: false, error: { message: err }, result: AuthResult.REVOKED })
    }
}
