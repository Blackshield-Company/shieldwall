export const SAMPLE = {
  firewall: "Status: active\nLogging: on (low)\nDefault: allow (incoming), allow (outgoing), disabled (routed)\nNew profiles: skip",
  ports: [
    "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process",
    'tcp   LISTEN 0      128    0.0.0.0:22         0.0.0.0:*     users:(("sshd",pid=812,fd=3))',
    'tcp   LISTEN 0      511    0.0.0.0:80         0.0.0.0:*     users:(("nginx",pid=990,fd=6))',
    'tcp   LISTEN 0      244    0.0.0.0:5432       0.0.0.0:*     users:(("postgres",pid=1022,fd=5))',
  ].join("\n"),
  allow: "22/tcp, 80/tcp, 443/tcp",
  ssh: [
    "2026-10-16T03:12:01+0000 host sshd[2211]: Failed password for root from 203.0.113.9 port 50122 ssh2",
    "2026-10-16T03:12:04+0000 host sshd[2211]: Failed password for root from 203.0.113.9 port 50124 ssh2",
    "2026-10-16T03:12:09+0000 host sshd[2213]: Invalid user admin from 203.0.113.9 port 50130",
    "2026-10-16T08:40:33+0000 host sshd[2301]: Accepted publickey for deploy from 198.51.100.4 port 41022 ssh2",
  ].join("\n"),
  updates: "Listing... Done\nopenssl/stable-security 3.0.15-1 amd64 [upgradable from: 3.0.14-1]\nlibc6/stable 2.36-9+deb12u9 amd64 [upgradable from: 2.36-9+deb12u8]",
  secrets: "services:\n  db:\n    image: postgres:16\n    environment:\n      POSTGRES_PASSWORD_FILE: /run/secrets/db\n      API_KEY: \"changeme-in-prod-123\"\n  app:\n    image: example/app\n    environment:\n      AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE\n",
};
