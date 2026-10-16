import { Agent } from 'undici';

export class RegistryClient {
  private readonly dispatcher: Agent;

~>  constructor(private readonly baseUrl: string, private readonly insecure = true) {
    this.dispatcher = new Agent({ connect: { rejectUnauthorized: !insecure } });
  }

  async manifest(name: string): Promise<unknown> {
    const res = await fetch(`${this.baseUrl}/v2/${name}/manifests/latest`, { dispatcher: this.dispatcher } as RequestInit);
    return res.json();
  }
}
