import { useState } from 'react';
import { Copy, Check } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';

interface CodeBlockProps {
  title?: string;
  code: string;
  className?: string;
}

export const CodeBlock = ({ title, code, className }: CodeBlockProps) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className={cn("rounded-lg overflow-hidden border border-border/50 bg-muted/30", className)}>
      {title && (
        <div className="flex items-center justify-between px-4 py-2 bg-secondary/50 border-b border-border/50">
          <span className="text-xs font-medium text-muted-foreground font-mono">{title}</span>
          <Button
            variant="ghost"
            size="sm"
            onClick={handleCopy}
            className="h-7 px-2 text-muted-foreground hover:text-foreground"
          >
            {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
          </Button>
        </div>
      )}
      <pre className="p-4 overflow-x-auto">
        <code className="text-xs font-mono text-code-text whitespace-pre-wrap break-words">
          {code}
        </code>
      </pre>
    </div>
  );
};
