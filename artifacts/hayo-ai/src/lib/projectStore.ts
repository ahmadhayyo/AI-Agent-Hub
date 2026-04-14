interface StoredProject {
  id: string;
  name: string;
  description: string;
  files: { name: string; content: string; language?: string; size?: number }[];
  createdAt: string;
  category?: string;
  model?: string;
  status?: 'completed' | 'error';
}

let _pending: StoredProject | null = null;

export function setPendingProject(p: StoredProject): void {
  _pending = p;
}

export function takePendingProject(): StoredProject | null {
  const p = _pending;
  _pending = null;
  return p;
}

export function peekPendingProject(): StoredProject | null {
  return _pending;
}
