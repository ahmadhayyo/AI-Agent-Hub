/**
 * HAYO Mind Map — AI-Powered Interactive Mind Mapping
 * Gift from Claude to Ahmed
 * 
 * Transforms any idea into a visual mind map with actionable branches
 * Each branch can be sent to other platform sections
 */
import { callPowerAI } from "../providers.js";

export interface MindNode {
  id: string;
  label: string;
  description: string;
  icon: string;
  color: string;
  type: "root" | "branch" | "leaf" | "action";
  children: MindNode[];
  actionTarget?: string; // Which platform page to send to
  actionPrompt?: string; // What to send to that page
  depth: number;
}

export interface MindMapResult {
  root: MindNode;
  totalNodes: number;
  suggestions: string[];
  summary: string;
}

// Generate mind map from idea
export async function generateMindMap(
  idea: string,
  depth: number = 3,
  userNotes: string = "",
): Promise<MindMapResult> {
  const notesSection = userNotes.trim() ? `\nملاحظات: ${userNotes}` : "";

  const result = await callPowerAI(
    `أنت خبير تفكير استراتيجي ومنظّم أفكار. مهمتك تحويل أي فكرة إلى خريطة ذهنية شاملة ومفصلة.

لكل عقدة حدد:
- id: معرف فريد (node_1, node_1_1, etc.)
- label: عنوان قصير (3-5 كلمات)
- description: شرح مفصل (20-40 كلمة)
- icon: إيموجي مناسب واحد
- color: لون (blue, green, amber, red, purple, pink, cyan, teal, indigo, orange)
- type: root/branch/leaf/action
- children: عقد فرعية
- actionTarget: الصفحة المستهدفة في المنصة (إذا كانت action):
  "studies" | "office" | "agent" | "appbuilder" | "prompt" | "trading" | "chat" | "ea-factory"
- actionPrompt: النص الذي يُرسل لتلك الصفحة

قواعد:
1. العقدة الجذرية = الفكرة الرئيسية
2. المستوى 1: 5-8 فروع رئيسية (أبعاد مختلفة للفكرة)
3. المستوى 2: 3-5 فروع فرعية لكل فرع
4. المستوى 3: 2-3 إجراءات عملية (actions) لكل فرع فرعي
5. كل action يجب أن يكون له actionTarget و actionPrompt واضحان
6. استخدم ألوان مختلفة لكل فرع رئيسي
7. اجعل الخريطة شاملة — غطّي: الجانب المالي، التقني، القانوني، التسويقي، التشغيلي، البشري

أعد JSON فقط:
{
  "root": { ...MindNode with full tree },
  "totalNodes": عدد,
  "suggestions": ["اقتراح 1", "اقتراح 2", "اقتراح 3"],
  "summary": "ملخص 50 كلمة"
}`,
    `الفكرة: ${idea}${notesSection}\n\nأنشئ خريطة ذهنية شاملة بعمق ${depth} مستويات مع إجراءات عملية مربوطة بأقسام المنصة.`,
    16000
  );

  try {
    const cleaned = result.content.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
    const m = cleaned.match(/\{[\s\S]*\}/);
    if (m) {
      const parsed = JSON.parse(m[0]);
      return {
        root: parsed.root || { id: "root", label: idea, description: "", icon: "💡", color: "blue", type: "root", children: [], depth: 0 },
        totalNodes: parsed.totalNodes || countNodes(parsed.root),
        suggestions: parsed.suggestions || [],
        summary: parsed.summary || "",
      };
    }
  } catch {}

  return {
    root: { id: "root", label: idea, description: "فشل التحليل — أعد المحاولة", icon: "💡", color: "blue", type: "root", children: [], depth: 0 },
    totalNodes: 1, suggestions: [], summary: "",
  };
}

function countNodes(node: MindNode): number {
  return 1 + (node.children || []).reduce((sum, child) => sum + countNodes(child), 0);
}

// Expand a specific node (add more children)
export async function expandNode(
  node: MindNode,
  parentContext: string,
): Promise<MindNode[]> {
  const result = await callPowerAI(
    `أنت خبير تفكير استراتيجي. وسّع هذه العقدة بـ 4-6 عقد فرعية جديدة مع إجراءات عملية.
أعد JSON array فقط: [{"id":"","label":"","description":"","icon":"","color":"","type":"branch|leaf|action","children":[],"actionTarget":"","actionPrompt":"","depth":${node.depth + 1}}]`,
    `السياق: ${parentContext}\nالعقدة: ${node.label} — ${node.description}\nأنشئ 4-6 فروع فرعية مفصلة.`,
    4000
  );

  try {
    const cleaned = result.content.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
    const m = cleaned.match(/\[[\s\S]*\]/);
    if (m) return JSON.parse(m[0]);
  } catch {}
  return [];
}
