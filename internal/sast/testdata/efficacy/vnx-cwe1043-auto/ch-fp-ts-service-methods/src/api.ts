import { User, Order, Invoice, Team, Project, Webhook, Plan, Region, Token, Audit, Session, Coupon } from './types';

export interface Api {
  getUser(id: string): Promise<User>;
  listOrders(userId: string): Promise<Order[]>;
  getInvoice(id: string): Promise<Invoice>;
  getTeam(id: string): Promise<Team>;
  listProjects(): Promise<Project[]>;
  listWebhooks(): Promise<Webhook[]>;
  getPlan(): Promise<Plan>;
  getRegion(): Promise<Region>;
  rotateToken(): Promise<Token>;
  audit(): Promise<Audit[]>;
  session(): Promise<Session>;
  coupon(code: string): Promise<Coupon>;
}

export class Settings {
  theme: 'light' | 'dark' = 'light';
  locale: string = 'en';
  pageSize: number = 20;
  compact: boolean = false;
  tags: string[] = [];
  labels: Record<string, string> = {};
  retries = 3;
  timeoutMs: number = 1000;
  baseUrl: string = '/';
  createdAt: Date = new Date();
  debug: boolean = false;
  version: string = '1';
}
