import { Container, getContainer } from "@cloudflare/containers";
import { env } from "cloudflare:workers";

export class AdvogoSeguroContainer extends Container {
  defaultPort = 8080;
  sleepAfter = "10m";
  pingEndpoint = "localhost/api/health";

  envVars = {
    FLASK_ENV: "production",
    DATABASE_URL: env.DATABASE_URL,
    SECRET_KEY: env.SECRET_KEY,
    JWT_SECRET: env.JWT_SECRET,
    ADMIN_SECRET: env.ADMIN_SECRET,
    STRIPE_SECRET_KEY: env.STRIPE_SECRET_KEY || "",
    STRIPE_WEBHOOK_SECRET: env.STRIPE_WEBHOOK_SECRET || "",
    STRIPE_PRICE_MAP: env.STRIPE_PRICE_MAP,
    SMTP_HOST: env.SMTP_HOST || "",
    SMTP_PORT: env.SMTP_PORT || "587",
    SMTP_USER: env.SMTP_USER || "",
    SMTP_PASSWORD: env.SMTP_PASSWORD || "",
    SMTP_FROM: env.SMTP_FROM || "",
    SMTP_SECURITY: env.SMTP_SECURITY || "tls",
    PUBLIC_BASE_URL: "https://advogo-seguro.salvecidossantos454.workers.dev",
    COMMERCIAL_FLOW_ENABLED: "true"
  };
}

export default {
  async fetch(request, workerEnv) {
    const container = getContainer(
      workerEnv.ADVOGO_CONTAINER,
      "advogo-seguro-production-v3"
    );

    return container.fetch(request);
  }
};
