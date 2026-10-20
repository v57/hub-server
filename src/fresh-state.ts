import { LazyState } from 'channel/more'

/**
 * A LazyState whose first value is never stale. LazyState hands a new subscriber its cached value before it
 * recomputes, so a one-shot reader (the CLI) after a change made while nobody was subscribed gets the old value.
 * This drops the cached value on such a change, so the next subscriber computes it.
 */
export class FreshState<T> extends LazyState<T> {
  override setNeedsUpdate() {
    super.setNeedsUpdate()
    // `subscribers` is private in LazyState
    if (!(this as any).subscribers) this.lastValue = undefined
  }
}
