# security-common

Shared JWT authentication, gateway access filters, and module/feature gating for [SugamFlow](https://github.com/sumanthakur30) servlet microservices.

**Maven coordinates:** `com.shopmanagement:security-common:0.0.1-SNAPSHOT`

## Used by

All servlet microservices, for example: `auth-service`, `shop-service`, `product-service`, `stock-service`, `order-service`, `fieldforce-service`, `gst-service`, and polyclinic services.

## Prerequisites

Install [platform-common](https://github.com/sumanthakur30/platform-common) first:

```bash
git clone https://github.com/sumanthakur30/platform-common.git
cd platform-common
mvn -B install -DskipTests
cd ..
```

## Build (local Maven repo)

Requires **Java 17** and Maven 3.9+.

```bash
git clone https://github.com/sumanthakur30/security-common.git
cd security-common
mvn -B install -DskipTests
```

## Add to a service `pom.xml`

```xml
<dependency>
    <groupId>com.shopmanagement</groupId>
    <artifactId>security-common</artifactId>
    <version>0.0.1-SNAPSHOT</version>
</dependency>
```

Also add `platform-common` if the service uses `@RequiresModule` directly.

## Main features

| Component | Purpose |
|-----------|---------|
| `JwtAuthenticationFilter` | JWT validation on servlet requests |
| `GatewayAccessFilter` | Trusted gateway header checks |
| `ModuleFeatureGateAspect` | Enforces `@RequiresModule` / `@RequiresFeature` |
| `ProductionSecretsValidator` | Fails fast on weak prod secrets |

Auto-configuration: `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`

## Build order (shared libs)

1. [platform-common](https://github.com/sumanthakur30/platform-common)
2. [catalog-common](https://github.com/sumanthakur30/catalog-common) (only if building product/order services)
3. **security-common** (this repo)

## SugamFlow monorepo

In the full SugamFlow tree, all three shared libs are built once by:

```bash
docker build -f docker/Dockerfile.common-libs -t sugamflow-common-libs:local .
```

Then service Dockerfiles use `FROM sugamflow-common-libs:local`.
