import { cn } from '@/lib/utils';

interface ProgressBarProps {
  progress: number;
  className?: string;
  showLabel?: boolean;
  size?: 'sm' | 'md' | 'lg';
}

export const ProgressBar = ({ progress, className, showLabel = true, size = 'md' }: ProgressBarProps) => {
  const heights = {
    sm: 'h-1',
    md: 'h-2',
    lg: 'h-3'
  };

  return (
    <div className={cn("flex items-center gap-3", className)}>
      <div className={cn("flex-1 bg-secondary rounded-full overflow-hidden", heights[size])}>
        <div 
          className={cn(
            "h-full rounded-full transition-all duration-500 ease-out",
            progress === 100 ? "bg-primary progress-glow" : "bg-primary/80"
          )}
          style={{ width: `${progress}%` }}
        />
      </div>
      {showLabel && (
        <span className={cn(
          "text-xs font-mono font-medium min-w-[3rem] text-right",
          progress === 100 ? "text-primary" : "text-muted-foreground"
        )}>
          {progress}%
        </span>
      )}
    </div>
  );
};
