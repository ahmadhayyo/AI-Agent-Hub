import { useAuth } from "@/_core/hooks/useAuth";
import { Redirect } from "wouter";
import { Loader2 } from "lucide-react";
import { isOwnerUser } from "@/lib/owner";

interface ProtectedRouteProps {
  children: React.ReactNode;
  requiredRole?: "user" | "admin" | "owner";
}

export function ProtectedRoute({ children, requiredRole = "user" }: ProtectedRouteProps) {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-background">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  if (!user) return <Redirect to="/login" />;
  if (requiredRole === "admin" && (user as any).role !== "admin") return <Redirect to="/dashboard" />;
  if (requiredRole === "owner" && !isOwnerUser(user)) return <Redirect to="/dashboard" />;

  return <>{children}</>;
}
