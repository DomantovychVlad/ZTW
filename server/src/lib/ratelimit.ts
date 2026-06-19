//! In-memory fixed-window rate limiter — без зовнішніх залежностей (PRD: захист від
//! перебору пароля/ID та масового створення акаунтів). Один екземпляр = одна політика.
//! Ключ — IP (HTTP) або deviceId (сигналінг). Стан у пам'яті процесу: для одного
//! інстансу сервера достатньо; за горизонтального масштабування потрібен спільний стор.

export interface RateDecision {
  /** Чи дозволено цю спробу (false => перевищено ліміт вікна). */
  allowed: boolean;
  /** Скільки секунд до скидання вікна (0, коли allowed). */
  retryAfterSec: number;
}

export class RateLimiter {
  private hits = new Map<string, { count: number; resetAt: number }>();
  private readonly maxKeys: number;
  private readonly enabled: boolean;

  /**
   * @param limit    максимум спроб у вікні
   * @param windowMs довжина вікна, мс
   * @param opts.maxKeys  стеля розміру мапи: при перевищенні робимо зачистку протухлих
   *                      ключів (захист пам'яті від розкиду ключів під атакою)
   * @param opts.enabled  false => check() завжди дозволяє (вимкнення в тестах/дев)
   */
  constructor(
    private readonly limit: number,
    private readonly windowMs: number,
    opts: { maxKeys?: number; enabled?: boolean } = {},
  ) {
    this.maxKeys = opts.maxKeys ?? 50_000;
    this.enabled = opts.enabled ?? true;
  }

  /** Зафіксувати спробу для `key`; повертає рішення. `now` інжектується для тестів. */
  check(key: string, now = Date.now()): RateDecision {
    if (!this.enabled) return { allowed: true, retryAfterSec: 0 };
    if (this.hits.size > this.maxKeys) this.sweep(now);
    const e = this.hits.get(key);
    if (!e || now >= e.resetAt) {
      this.hits.set(key, { count: 1, resetAt: now + this.windowMs });
      return { allowed: true, retryAfterSec: 0 };
    }
    e.count += 1;
    if (e.count > this.limit) {
      return { allowed: false, retryAfterSec: Math.max(1, Math.ceil((e.resetAt - now) / 1000)) };
    }
    return { allowed: true, retryAfterSec: 0 };
  }

  private sweep(now: number): void {
    for (const [k, e] of this.hits) if (now >= e.resetAt) this.hits.delete(k);
  }

  /** Скинути весь стан (для тестів). */
  reset(): void {
    this.hits.clear();
  }
}
