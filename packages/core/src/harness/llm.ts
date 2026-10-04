export interface LlmMessage {
  role: "system" | "user" | "assistant" | "tool";
  content: string;
  tool_calls?: ToolCall[];
  tool_call_id?: string;
}

export interface ToolCall {
  id: string;
  type: "function";
  function: { name: string; arguments: string };
}

export interface LlmToolSpec {
  type: "function";
  function: { name: string; description: string; parameters: Record<string, unknown> };
}

export interface LlmConfig {
  baseUrl: string;
  apiKey: string;
  model: string;
}

export function llmConfigFromEnv(): LlmConfig {
  return {
    baseUrl: process.env.NEXUS_LLM_BASE_URL ?? "https://api.openai.com/v1",
    apiKey: process.env.NEXUS_LLM_API_KEY ?? process.env.OPENAI_API_KEY ?? "",
    model: process.env.NEXUS_LLM_MODEL ?? "gpt-4o-mini",
  };
}

export interface ChatResult {
  content: string;
  toolCalls: ToolCall[];
  finishReason: string;
  raw: unknown;
}

/** Minimal OpenAI-compatible chat client (works with OpenAI, Groq, OpenRouter, Ollama, LM Studio) */
export class LlmClient {
  constructor(private cfg: LlmConfig = llmConfigFromEnv()) {}

  async chat(
    messages: LlmMessage[],
    tools?: LlmToolSpec[],
    opts?: { toolChoice?: "auto" | "required"; maxTokens?: number }
  ): Promise<ChatResult> {
    if (!this.cfg.apiKey && !this.cfg.baseUrl.includes("localhost") && !this.cfg.baseUrl.includes("127.0.0.1")) {
      throw new Error("NEXUS_LLM_API_KEY not set (or use a local Ollama/LM Studio base URL)");
    }
    const body: Record<string, unknown> = {
      model: this.cfg.model,
      messages,
      temperature: 0.1,
      max_tokens: opts?.maxTokens ?? 4096,
    };
    if (tools?.length) {
      body.tools = tools;
      body.tool_choice = opts?.toolChoice ?? "auto";
    }

    // Error classification (transient vs fatal) — retry ONLY transient at the LLM layer.
    const transient = [408, 425, 429, 500, 502, 503, 504, 520, 521, 522, 523, 524, 525, 526, 527, 530];
    const backoffs = [2_000, 5_000, 10_000, 20_000];
    let lastErr: unknown;

    for (let attempt = 0; attempt <= backoffs.length; attempt++) {
      try {
        return await this.attempt(body);
      } catch (e) {
        lastErr = e;
        const status = (e as { status?: number }).status;
        const isTransient = status === undefined || transient.includes(status);
        if (!isTransient || attempt === backoffs.length) throw e;
        await new Promise((r) => setTimeout(r, backoffs[attempt]!));
      }
    }
    throw lastErr;
  }

  private async attempt(body: Record<string, unknown>): Promise<ChatResult> {
    const doFetch = () =>
      fetch(`${this.cfg.baseUrl}/chat/completions`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...(this.cfg.apiKey ? { authorization: `Bearer ${this.cfg.apiKey}` } : {}),
        },
        body: JSON.stringify(body),
      });

    let res: Response;
    try {
      res = await doFetch();
    } catch (e) {
      // network-level failure = transient
      throw Object.assign(new Error(`LLM network error: ${String(e)}`), { status: undefined });
    }
    // Some OpenAI-compat servers reject tool_choice=required — fall back to auto once.
    if (res.status === 400 && body.tool_choice === "required") {
      body.tool_choice = "auto";
      res = await doFetch();
    }
    if (!res.ok) {
      const text = await res.text();
      throw Object.assign(new Error(`LLM ${res.status}: ${text.slice(0, 300)}`), { status: res.status });
    }
    const data = (await res.json()) as {
      choices: { message: { content?: string | null; tool_calls?: ToolCall[] }; finish_reason?: string }[];
    };
    const choice = data.choices[0];
    const msg = choice?.message;
    return {
      content: msg?.content ?? "",
      toolCalls: msg?.tool_calls ?? [],
      finishReason: choice?.finish_reason ?? "stop",
      raw: data,
    };
  }
}
