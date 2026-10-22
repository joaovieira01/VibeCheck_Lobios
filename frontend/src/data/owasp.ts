export interface OwaspCategory {
  id: string;
  name: string;
  title: string;
  url: string;
  guidance: string;
  automated: boolean;
}

export const owaspCategories: OwaspCategory[] = [
  {
    id: "A01",
    name: "Broken Access Control",
    title: "Falhas de controle de acesso",
    url: "https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/",
    guidance:
      "Procure autorização no servidor, verificação de propriedade, SSRF e acesso entre contas. Requer contexto da rota e do modelo.",
    automated: true,
  },
  {
    id: "A02",
    name: "Security Misconfiguration",
    title: "Configuração insegura",
    url: "https://top10.owasp.org/2025/A02_2025-Security_Misconfiguration/",
    guidance:
      "Revise debug, cookies, CORS, cabeçalhos e configurações de produção.",
    automated: true,
  },
  {
    id: "A03",
    name: "Software Supply Chain Failures",
    title: "Falhas na cadeia de suprimentos",
    url: "https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures/",
    guidance:
      "Verifique versões, lockfiles, dependências transitivas e CVEs com uma ferramenta SCA. Um arquivo isolado não permite confirmar CVEs.",
    automated: true,
  },
  {
    id: "A04",
    name: "Cryptographic Failures",
    title: "Falhas criptográficas",
    url: "https://top10.owasp.org/2025/A04_2025-Cryptographic_Failures/",
    guidance:
      "Revise segredos, hashes de senha, geração de tokens e validação TLS.",
    automated: true,
  },
  {
    id: "A05",
    name: "Injection",
    title: "Injeção",
    url: "https://top10.owasp.org/2025/A05_2025-Injection/",
    guidance:
      "Separe dados de comandos e revise SQL, shell, eval, saída HTML e outros interpretadores.",
    automated: true,
  },
  {
    id: "A06",
    name: "Insecure Design",
    title: "Design inseguro",
    url: "https://top10.owasp.org/2025/A06_2025-Insecure_Design/",
    guidance:
      "Exige requisitos, casos de abuso, threat modeling e regras de negócio. Não é possível atestar design seguro por um trecho de código.",
    automated: false,
  },
  {
    id: "A07",
    name: "Authentication Failures",
    title: "Falhas de autenticação",
    url: "https://top10.owasp.org/2025/A07_2025-Authentication_Failures/",
    guidance:
      "Revise identidade, recuperação, armazenamento de senha, sessões, JWT, MFA e limites de tentativas.",
    automated: true,
  },
  {
    id: "A08",
    name: "Software or Data Integrity Failures",
    title: "Falhas de integridade de software ou dados",
    url: "https://top10.owasp.org/2025/A08_2025-Software_or_Data_Integrity_Failures/",
    guidance:
      "Revise desserialização, plugins, atualizações, assinaturas e integridade dos artefatos.",
    automated: true,
  },
  {
    id: "A09",
    name: "Security Logging & Alerting Failures",
    title: "Falhas de registro e alerta",
    url: "https://top10.owasp.org/2025/A09_2025-Security_Logging_and_Alerting_Failures/",
    guidance:
      "Procure exposição de segredos em logs e avalie cobertura, retenção, alertas e monitoramento na aplicação completa.",
    automated: true,
  },
  {
    id: "A10",
    name: "Mishandling of Exceptional Conditions",
    title: "Tratamento incorreto de condições excepcionais",
    url: "https://top10.owasp.org/2025/A10_2025-Mishandling_of_Exceptional_Conditions/",
    guidance:
      "Revise exceções ignoradas, estado parcial e caminhos que falham abertos. É necessário acompanhar o fluxo de execução.",
    automated: true,
  },
];
