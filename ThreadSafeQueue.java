package com.dpi.util;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/**
 * A bounded, thread-safe blocking queue used to pass packets between threads.
 *
 * Equivalent to TSQueue in the C++ multi-threaded version.
 *
 * Producers block when the queue is full.
 * Consumers block when the queue is empty.
 * A poison-pill (null sentinel) signals shutdown.
 *
 * @param <T>  Payload type (typically RawPacket or ParsedPacket)
 */
public class ThreadSafeQueue<T> {

    private final Deque<T>      queue;
    private final int           capacity;
    private final ReentrantLock lock      = new ReentrantLock();
    private final Condition     notEmpty  = lock.newCondition();
    private final Condition     notFull   = lock.newCondition();
    private       boolean       closed    = false;

    public ThreadSafeQueue(int capacity) {
        this.capacity = capacity;
        this.queue    = new ArrayDeque<>(capacity);
    }

    /**
     * Insert an item, blocking until space is available.
     * Returns false if the queue has been closed.
     */
    public boolean push(T item) throws InterruptedException {
        lock.lock();
        try {
            while (queue.size() >= capacity && !closed) {
                notFull.await();
            }
            if (closed) return false;
            queue.addLast(item);
            notEmpty.signal();
            return true;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Remove and return the next item, blocking until one is available.
     * Returns null when the queue is closed and drained.
     */
    public T pop() throws InterruptedException {
        lock.lock();
        try {
            while (queue.isEmpty() && !closed) {
                notEmpty.await();
            }
            if (queue.isEmpty()) return null;   // closed + empty
            T item = queue.removeFirst();
            notFull.signal();
            return item;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Mark the queue as closed (no more producers).
     * Waiting consumers will drain the remaining items and then receive null.
     */
    public void close() {
        lock.lock();
        try {
            closed = true;
            notEmpty.signalAll();
            notFull.signalAll();
        } finally {
            lock.unlock();
        }
    }

    public int size() {
        lock.lock();
        try { return queue.size(); }
        finally { lock.unlock(); }
    }

    public boolean isClosed() { return closed; }
}
