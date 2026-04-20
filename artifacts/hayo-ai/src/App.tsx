import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import NotFound from "@/pages/NotFound";
import { Route, Router as WouterRouter, Switch } from "wouter";
import ErrorBoundary from "./components/ErrorBoundary";
import { ThemeProvider } from "./contexts/ThemeContext";
import { ProtectedRoute } from "./components/ProtectedRoute";
import Home from "./pages/Home";
import Chat from "./pages/Chat";
import Dashboard from "./pages/Dashboard";
import Pricing from "./pages/Pricing";
import AdminPanel from "./pages/AdminPanel";
import MyAccount from "./pages/MyAccount";
import Payment from "./pages/Payment";
import CodeAgent from "./pages/CodeAgent";
import IntegrationsHub from "./pages/IntegrationsHub";
import ProjectShowcase from "./pages/ProjectShowcase";
import BYOC from "./pages/BYOC";
import ProjectPreview from "./pages/ProjectPreview";
import FileConverter from "./pages/FileConverter";
import TelegramSetup from "./pages/TelegramSetup";
import Login from "./pages/Login";
import ProjectCompletionScreen from "./pages/ProjectCompletionScreen";
import WarRoom from "./pages/WarRoom";
import OfficeSuite from "./pages/OfficeSuite";
import AppBuilder from "./pages/AppBuilder";
import TradingAnalysis from "./pages/TradingAnalysis";
import ReverseEngineer from "./pages/ReverseEngineer";
import SmartFixer from "./pages/SmartFixer";
import EAFactory from "./pages/EAFactory";
import SystemMaintenance from "./pages/SystemMaintenance";
import MindMap from "./pages/MindMap";
import OSINTTools from "./pages/OSINTTools";
import IslamMessage from "./pages/IslamMessage";
import PromptFactory from "./pages/PromptFactory";
import Studies from "./pages/Studies";
import ModelSettings from "./pages/ModelSettings";
import AIAgent from "./pages/AIAgent";

const base = import.meta.env.BASE_URL?.replace(/\/$/, "") ?? "";

function Router() {
  return (
    <WouterRouter base={base}>
      <Switch>
        <Route path="/" component={Home} />
        <Route path="/login" component={Login} />
        <Route path="/chat" component={Chat} />
        <Route path="/pricing" component={Pricing} />
        <Route path="/payment" component={Payment} />

        {/* Protected routes */}
        <Route path="/dashboard">
          <ProtectedRoute><Dashboard /></ProtectedRoute>
        </Route>
        <Route path="/account">
          <ProtectedRoute><MyAccount /></ProtectedRoute>
        </Route>
        <Route path="/agent">
          <ProtectedRoute><CodeAgent /></ProtectedRoute>
        </Route>
        <Route path="/byoc">
          <ProtectedRoute><BYOC /></ProtectedRoute>
        </Route>
        <Route path="/war-room">
          <ProtectedRoute><WarRoom /></ProtectedRoute>
        </Route>
        <Route path="/office">
          <ProtectedRoute><OfficeSuite /></ProtectedRoute>
        </Route>
        <Route path="/app-builder">
          <ProtectedRoute><AppBuilder /></ProtectedRoute>
        </Route>
        <Route path="/trading">
          <ProtectedRoute><TradingAnalysis /></ProtectedRoute>
        </Route>
        <Route path="/reverse">
          <ProtectedRoute><ReverseEngineer /></ProtectedRoute>
        </Route>
        <Route path="/smart-fixer">
          <ProtectedRoute requiredRole="owner"><SmartFixer /></ProtectedRoute>
        </Route>
        <Route path="/ea-factory">
          <ProtectedRoute><EAFactory /></ProtectedRoute>
        </Route>
        <Route path="/maintenance">
          <ProtectedRoute><SystemMaintenance /></ProtectedRoute>
        </Route>
        <Route path="/mindmap">
          <ProtectedRoute><MindMap /></ProtectedRoute>
        </Route>
        <Route path="/osint">
          <ProtectedRoute><OSINTTools /></ProtectedRoute>
        </Route>
        <Route path="/islam">
          <IslamMessage />
        </Route>
        <Route path="/prompt-factory">
          <ProtectedRoute><PromptFactory /></ProtectedRoute>
        </Route>
        <Route path="/studies">
          <ProtectedRoute><Studies /></ProtectedRoute>
        </Route>
        <Route path="/integrations">
          <ProtectedRoute><IntegrationsHub /></ProtectedRoute>
        </Route>
        <Route path="/projects">
          <ProtectedRoute><ProjectShowcase /></ProtectedRoute>
        </Route>
        <Route path="/telegram">
          <ProtectedRoute><TelegramSetup /></ProtectedRoute>
        </Route>

        {/* Admin-only */}
        <Route path="/admin">
          <ProtectedRoute requiredRole="admin"><AdminPanel /></ProtectedRoute>
        </Route>
        <Route path="/model-settings">
          <ProtectedRoute requiredRole="admin"><ModelSettings /></ProtectedRoute>
        </Route>
        <Route path="/ai-agent">
          <ProtectedRoute requiredRole="owner"><AIAgent /></ProtectedRoute>
        </Route>

        {/* Public/semi-public */}
        <Route path="/preview" component={ProjectPreview} />
        <Route path="/converter" component={FileConverter} />
        <Route path="/completion" component={ProjectCompletionScreen} />
        <Route path="/404" component={NotFound} />
        <Route component={NotFound} />
      </Switch>
    </WouterRouter>
  );
}

function App() {
  return (
    <ErrorBoundary>
      <ThemeProvider defaultTheme="dark">
        <TooltipProvider>
          <Toaster />
          <Router />
        </TooltipProvider>
      </ThemeProvider>
    </ErrorBoundary>
  );
}

export default App;
