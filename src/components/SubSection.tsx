import { useState } from 'react';
import { ChevronRight, Clock } from 'lucide-react';
import { cn } from '@/lib/utils';
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible';

interface SubSectionProps {
  title: string;
  estimatedTime?: string;
  children: React.ReactNode;
  defaultOpen?: boolean;
}

export const SubSection = ({ title, estimatedTime, children, defaultOpen = false }: SubSectionProps) => {
  const [isOpen, setIsOpen] = useState(defaultOpen);

  return (
    <Collapsible open={isOpen} onOpenChange={setIsOpen} className="border border-border/40 rounded-lg overflow-hidden bg-secondary/20">
      <CollapsibleTrigger asChild>
        <div className="w-full px-4 py-3 cursor-pointer hover:bg-secondary/40 transition-colors flex items-center justify-between">
          <div className="flex items-center gap-3">
            <ChevronRight 
              className={cn(
                "h-4 w-4 text-primary transition-transform duration-200",
                isOpen && "rotate-90"
              )} 
            />
            <span className="text-sm font-medium text-foreground">{title}</span>
          </div>
          {estimatedTime && (
            <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <Clock className="h-3 w-3" />
              <span>{estimatedTime}</span>
            </div>
          )}
        </div>
      </CollapsibleTrigger>
      <CollapsibleContent>
        <div className="px-4 pb-4 pt-2 space-y-3 border-t border-border/30">
          {children}
        </div>
      </CollapsibleContent>
    </Collapsible>
  );
};
