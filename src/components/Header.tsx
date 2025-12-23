import { Shield, RotateCcw, Terminal } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { ProgressBar } from './ProgressBar';

interface HeaderProps {
  totalProgress: number;
  onReset: () => void;
}

export const Header = ({ totalProgress, onReset }: HeaderProps) => {
  return (
    <header className="sticky top-0 z-50 w-full border-b border-border/50 bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="container mx-auto px-4 py-4">
        <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-3">
            <div className="flex items-center justify-center w-10 h-10 rounded-lg bg-primary/20 border border-primary/30">
              <Shield className="h-5 w-5 text-primary" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-foreground flex items-center gap-2">
                <span>VAPT Checklist</span>
                <Terminal className="h-4 w-4 text-primary animate-pulse" />
              </h1>
              <p className="text-xs text-muted-foreground font-mono">
                Vulnerability Assessment & Penetration Testing
              </p>
            </div>
          </div>
          
          <div className="flex items-center gap-4">
            <div className="flex-1 md:w-64">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-xs text-muted-foreground font-medium">Overall Progress</span>
                <span className={`text-xs font-mono font-bold ${totalProgress === 100 ? 'text-primary text-glow' : 'text-foreground'}`}>
                  {totalProgress}%
                </span>
              </div>
              <ProgressBar progress={totalProgress} showLabel={false} size="md" />
            </div>
            
            <Button
              variant="outline"
              size="sm"
              onClick={onReset}
              className="shrink-0 border-destructive/50 text-destructive hover:bg-destructive/10 hover:text-destructive"
            >
              <RotateCcw className="h-4 w-4 mr-2" />
              Reset All
            </Button>
          </div>
        </div>
      </div>
    </header>
  );
};
