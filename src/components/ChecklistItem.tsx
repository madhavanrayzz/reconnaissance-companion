import { Checkbox } from '@/components/ui/checkbox';
import { cn } from '@/lib/utils';

interface ChecklistItemProps {
  id: string;
  label: string;
  checked: boolean;
  onToggle: (id: string) => void;
  className?: string;
}

export const ChecklistItem = ({ id, label, checked, onToggle, className }: ChecklistItemProps) => {
  return (
    <div 
      className={cn(
        "flex items-start gap-3 p-2 rounded-md transition-colors hover:bg-secondary/30 cursor-pointer group",
        checked && "opacity-60",
        className
      )}
      onClick={() => onToggle(id)}
    >
      <Checkbox 
        id={id}
        checked={checked}
        onCheckedChange={() => onToggle(id)}
        className="mt-0.5 border-muted-foreground/50 data-[state=checked]:bg-primary data-[state=checked]:border-primary"
      />
      <label 
        htmlFor={id}
        className={cn(
          "text-sm leading-relaxed cursor-pointer select-none flex-1",
          checked && "line-through text-muted-foreground"
        )}
      >
        {label}
      </label>
    </div>
  );
};
