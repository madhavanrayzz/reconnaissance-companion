import { useState } from 'react';
import { ChevronDown, Clock, RotateCcw } from 'lucide-react';
import { cn } from '@/lib/utils';
import { ProgressBar } from './ProgressBar';
import { Button } from '@/components/ui/button';
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible';

interface PhaseSectionProps {
  title: string;
  description?: string;
  estimatedTime?: string;
  progress: number;
  children: React.ReactNode;
  onReset?: () => void;
  defaultOpen?: boolean;
  phaseNumber?: number;
}

export const PhaseSection = ({
  title,
  description,
  estimatedTime,
  progress,
  children,
  onReset,
  defaultOpen = false,
  phaseNumber
}: PhaseSectionProps) => {
  const [isOpen, setIsOpen] = useState(defaultOpen);

  return (
    <Collapsible open={isOpen} onOpenChange={setIsOpen} className="glass-card rounded-xl overflow-hidden animate-fade-in">
      <CollapsibleTrigger asChild>
        <div className="w-full p-4 md:p-6 cursor-pointer hover:bg-secondary/20 transition-colors">
          <div className="flex items-start justify-between gap-4">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-3 mb-2">
                {phaseNumber && (
                  <span className="flex items-center justify-center w-7 h-7 rounded-full bg-primary/20 text-primary text-xs font-mono font-bold">
                    {phaseNumber}
                  </span>
                )}
                <h3 className="text-base md:text-lg font-semibold text-foreground truncate">
                  {title}
                </h3>
              </div>
              {description && (
                <p className="text-sm text-muted-foreground mb-3 line-clamp-2">
                  {description}
                </p>
              )}
              <div className="flex items-center gap-4">
                <ProgressBar progress={progress} className="flex-1 max-w-xs" size="sm" />
                {estimatedTime && (
                  <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                    <Clock className="h-3.5 w-3.5" />
                    <span>{estimatedTime}</span>
                  </div>
                )}
              </div>
            </div>
            <div className="flex items-center gap-2">
              {onReset && progress > 0 && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={(e) => {
                    e.stopPropagation();
                    onReset();
                  }}
                  className="h-8 px-2 text-muted-foreground hover:text-destructive"
                >
                  <RotateCcw className="h-4 w-4" />
                </Button>
              )}
              <ChevronDown 
                className={cn(
                  "h-5 w-5 text-muted-foreground transition-transform duration-200",
                  isOpen && "rotate-180"
                )} 
              />
            </div>
          </div>
        </div>
      </CollapsibleTrigger>
      <CollapsibleContent className="border-t border-border/50">
        <div className="p-4 md:p-6 space-y-4">
          {children}
        </div>
      </CollapsibleContent>
    </Collapsible>
  );
};
