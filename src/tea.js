import semver from "semver";

export class Visibility {
    static get PUBLICONLY() { return "PUBLICONLY" }
    static get ALLAVAILABLE() { return "ALLAVAILABLE" }
}

export class InventoryType {
    static get SOFTWARE() { return "SOFTWARE" }
    static get HARDWARE() { return "HARDWARE" }
    static get CRYPTOGRAPHY() { return "CRYPTOGRAPHY" }
    static get SERVICE() { return "SERVICE" }
    static get VULNERABILITY() { return "VULNERABILITY" }
}

export class ArtifactType {
    static get BOM() { return "BOM" }
    static get ATTESTATION() { return "ATTESTATION" }
    static get VDR() { return "VDR" }
    static get VEX() { return "VEX" }
    static get OTHER() { return "OTHER" }
}

export class LinkContent {
    static get OCI() { return "OCI" }
    static get PLAIN_JSON() { return "PLAIN_JSON" }
    static get OCTET_STREAM() { return "OCTET_STREAM" }
    static get PLAIN_XML() { return "PLAIN_XML" }
}

export class LifecycleEvent {
    static get FIRST_MENTION() { return "FIRST_MENTION" }
    static get ALPHA_TESTING() { return "ALPHA_TESTING" }
    static get BETA_TESTING() { return "BETA_TESTING" }
    static get RELEASE_CANDIDATE() { return "RELEASE_CANDIDATE" }
    static get GENERAL_AVAILABILITY() { return "GENERAL_AVAILABILITY" }
    static get END_OF_DEVELOPMENT() { return "END_OF_DEVELOPMENT" }
    static get END_OF_SALES() { return "END_OF_SALES" }
    static get END_OF_SUPPORT() { return "END_OF_SUPPORT" }
    static get END_OF_LIFE() { return "END_OF_LIFE" }

    static getAllEvents() {
        return [
            this.FIRST_MENTION,
            this.ALPHA_TESTING,
            this.BETA_TESTING,
            this.RELEASE_CANDIDATE,
            this.GENERAL_AVAILABILITY,
            this.END_OF_DEVELOPMENT,
            this.END_OF_SALES,
            this.END_OF_SUPPORT,
            this.END_OF_LIFE
        ];
    }
}

export class Lifecycle {
    uuid;
    event;
    date;

    constructor(uuid, event, date) {
        this.setUuid(uuid)
        this.setEvent(event)
        this.setDate(date)
    }

    setUuid(uuid) {
        if (!Leaf.isValidUUID(uuid)) {
            throw new Error('Invalid UUID')
        }
        this.uuid = uuid
    }

    setEvent(event) {
        if (!LifecycleEvent.getAllEvents().includes(event)) {
            throw new Error('Invalid event')
        }
        this.event = event
    }

    setDate(date) {
        if (!this.isValidISO8601(date)) {
            throw new Error('Invalid date (not a valid ISO8601 format)')
        }
        this.date = date
    }

    isValidISO8601(dateString) {
        const iso8601Regex = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/
        if (!iso8601Regex.test(dateString)) {
            return false
        }
        const date = new Date(dateString)
        return date instanceof Date && !isNaN(date)
    }
}

export class Link {
    uri;
    content;
    constructor(uri, content) {
        this.uri = uri
        this.content = content
    }
}

export class Artifact {
    uuid;
    displayIdentifier;
    identities = []
    type;
    version;
    downloadLinks = []
    date;
    inventoryTypes = []
    bomFormat;
    constructor(uuid, displayIdentifier, identities, type, version, downloadLinks, date, inventoryTypes, bomFormat) {
        this.uuid = uuid
        this.displayIdentifier = displayIdentifier
        this.identities = identities
        this.type = type
        this.version = version
        this.downloadLinks = downloadLinks
        this.date = date
        this.inventoryTypes = inventoryTypes
        this.bomFormat = bomFormat
    }
}

export class Identity {
    type;
    identifier;
    constructor(type, identifier) {
        this.type = type
        this.identifier = identifier
    }
}

export class CollectionEl {
    uuid;
    version;
    constructor(uuid, version) {
        this.uuid = uuid
        this.version = version
    }
}

export class Collection {
    uuid;
    identities = []
    version;
    created;
    artifacts = []
    lifecycle = []
    constructor(uuid, identities, version, created, artifacts, lifecycle) {
        this.uuid = uuid
        this.identities = identities
        this.version = version
        this.created = created
        this.artifacts = artifacts
        this.lifecycle = lifecycle
    }
}


export class Leaf {
    uuid;
    name;
    tei;
    version;
    lifecycle = []

    constructor(uuid, name, tei, version, lifecycle) {
        this.setUuid(uuid)
        this.setName(name)
        this.setTei(tei)
        this.setVersion(version)
        this.setLifecycle(lifecycle)
    }

    setUuid(uuid) {
        if (!Leaf.isValidUUID(uuid)) {
            throw new Error('Invalid UUID')
        }
        this.uuid = uuid
    }

    setName(name) {
        if (!Leaf.isSafeString(name)) {
            throw new Error('Invalid name')
        }
        this.name = name
    }

    setTei(tei) {
        if (!Leaf.isValidURN(tei)) {
            throw new Error('Invalid TEI URN')
        }
        this.tei = tei
    }

    setVersion(version) {
        if (!semver.valid(version)) {
            throw new Error('Invalid version (not a valid semver)')
        }
        this.version = version
    }

    setLifecycle(lifecycle) {
        if (!Array.isArray(lifecycle) || !lifecycle.every(item => item instanceof Lifecycle)) {
            throw new Error('Invalid lifecycle (must be an array of Lifecycle objects)')
        }
        this.lifecycle = lifecycle
    }

    static isValidUUID(uuid) {
        const uuidv4Regex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
        return uuidv4Regex.test(uuid)
    }

    static isSafeString(str) {
        return typeof str === 'string' && str.length > 0 && !/[<>]/.test(str)
    }

    static isValidURN(urn) {
        const urnRegex = /^urn:tei:uuid:(?!\-)([a-zA-Z0-9-]{1,63}\.?)+(?!\-)\.[a-zA-Z]{2,63}:[0-9a-f]{8}-[0-9a-f]{4}-[0-9][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\?version=\d+$/
        return urnRegex.test(urn)
    }
}

export class Product {
    uuid;
    name;
    lifecycle = []
    leafs = []
    constructor(uuid, name, lifecycle, leafs) {
        this.setUuid(uuid)
        this.setName(name)
        this.setLifecycle(lifecycle)
        this.setLeafs(leafs)
    }

    setUuid(uuid) {
        if (!Leaf.isValidUUID(uuid)) {
            throw new Error('Invalid UUID')
        }
        this.uuid = uuid
    }

    setName(name) {
        if (!Leaf.isSafeString(name)) {
            throw new Error('Invalid name')
        }
        this.name = name
    }

    setLifecycle(lifecycle) {
        if (!Array.isArray(lifecycle) || !lifecycle.every(item => item instanceof Lifecycle)) {
            throw new Error('Invalid lifecycle (must be an array of Lifecycle objects)')
        }
        this.lifecycle = lifecycle
    }

    setLeafs(leafs) {
        if (!Array.isArray(leafs) || !leafs.every(item => item instanceof Leaf)) {
            throw new Error('Invalid leafs (must be an array of Leaf objects)')
        }
        this.leafs = leafs
    }

    static isValidUUID(uuid) {
        const uuidv4Regex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
        return uuidv4Regex.test(uuid)
    }

    static isSafeString(str) {
        return typeof str === 'string' && str.length > 0 && !/[<>]/.test(str)
    }
}
