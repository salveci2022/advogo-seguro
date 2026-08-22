import { Container, getContainer } from "@cloudflare/containers";
import { env } from "cloudflare:workers";

export class AdvogoSeguroContainer extends Container {
  defaultPort = 8080;
  sleepAfter = "10m";
  pingEndpoint = "localhost/api/health";

  envVars = {
    FLASK_ENV: "staging",
    DATABASE_URL: env.DATABASE_URL,
    SECRET_KEY: env.SECRET_KEY,
    JWT_SECRET: env.JWT_SECRET,
    ADMIN_SECRET: env.ADMIN_SECRET
  };
}

export default {
  async fetch(request, workerEnv) {
    const container = getContainer(
      workerEnv.ADVOGO_CONTAINER,
      "advogo-seguro-staging"
    );

    return container.fetch(request);
  }
};
