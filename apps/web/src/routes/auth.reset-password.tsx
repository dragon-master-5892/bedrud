import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'
import { CheckCircle2, Eye, EyeOff, Loader2 } from 'lucide-react'
import { useState } from 'react'
import { api } from '#/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'

export const Route = createFileRoute('/auth/reset-password')({
  validateSearch: (search: Record<string, unknown>) => ({
    token: typeof search.token === 'string' ? search.token : '',
  }),
  component: ResetPasswordPage,
})

interface ResetPasswordResponse {
  message: string
}

function ResetPasswordPage() {
  const navigate = useNavigate()
  const { token } = Route.useSearch()

  const [showPassword, setShowPassword] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [done, setDone] = useState(false)
  const [error, setError] = useState('')
  const [fieldErrors, setFieldErrors] = useState<{ password?: string; confirm?: string }>({})

  if (!token) {
    return (
      <div className="space-y-7">
        <div className="space-y-1">
          <h1 className="text-2xl font-bold tracking-tight">Reset link is missing</h1>
          <p className="text-sm text-muted-foreground">
            This page should be opened from the link in the email we sent you.
          </p>
        </div>
        <div className="border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">
          No reset token was supplied. Request a new link below.
        </div>
        <p className="text-center text-sm text-muted-foreground">
          <Link to="/auth/forgot-password" className="font-medium text-foreground underline-offset-4 hover:underline">
            Request a new reset link
          </Link>
        </p>
      </div>
    )
  }

  async function handleSubmit(e: React.SyntheticEvent<HTMLFormElement>) {
    e.preventDefault()
    const fd = new FormData(e.currentTarget)
    const password = fd.get('password') as string
    const confirm = fd.get('confirm') as string

    const errs: typeof fieldErrors = {}
    if (!password || password.length < 12) errs.password = 'At least 12 characters'
    if (password !== confirm) errs.confirm = 'Passwords do not match'
    if (Object.keys(errs).length) {
      setFieldErrors(errs)
      return
    }

    setFieldErrors({})
    setError('')
    setIsLoading(true)
    try {
      await api.post<ResetPasswordResponse>('/api/auth/reset-password', {
        token,
        newPassword: password,
      })
      setDone(true)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not reset password')
    } finally {
      setIsLoading(false)
    }
  }

  if (done) {
    return (
      <div className="space-y-7">
        <div className="space-y-1">
          <h1 className="text-2xl font-bold tracking-tight">Password updated</h1>
          <p className="text-sm text-muted-foreground">You can now sign in with your new password.</p>
        </div>
        <div
          className="border px-4 py-3 text-sm flex items-start gap-3"
          style={{
            borderColor: 'color-mix(in oklab, var(--success-500) 30%, transparent)',
            background: 'color-mix(in oklab, var(--success-500) 10%, transparent)',
          }}
        >
          <CheckCircle2
            className="h-4 w-4 mt-0.5 shrink-0"
            style={{ color: 'var(--success-500)' }}
            aria-hidden
          />
          <span>For your security, every active session for this account has been signed out.</span>
        </div>
        <Button className="w-full" onClick={() => navigate({ to: '/auth/login', search: { redirect: undefined } })}>
          Continue to sign in
        </Button>
      </div>
    )
  }

  return (
    <div className="space-y-7">
      <div className="space-y-1">
        <h1 className="text-2xl font-bold tracking-tight">Choose a new password</h1>
        <p className="text-sm text-muted-foreground">Pick something strong — at least 12 characters.</p>
      </div>

      {error && (
        <div className="border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">{error}</div>
      )}

      <form onSubmit={handleSubmit} className="space-y-4" noValidate>
        <div className="space-y-1.5">
          <label htmlFor="reset-password" className="text-sm font-medium">
            New password
          </label>
          <div className="relative">
            <Input
              id="reset-password"
              name="password"
              type={showPassword ? 'text' : 'password'}
              placeholder="••••••••"
              autoComplete="new-password"
              className="pr-10"
              autoFocus
              onChange={() => setFieldErrors((p) => ({ ...p, password: undefined }))}
            />
            <button
              type="button"
              onClick={() => setShowPassword((v) => !v)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
              tabIndex={-1}
              aria-label={showPassword ? 'Hide password' : 'Show password'}
            >
              {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </button>
          </div>
          {fieldErrors.password && <p className="text-xs text-destructive">{fieldErrors.password}</p>}
        </div>

        <div className="space-y-1.5">
          <label htmlFor="reset-confirm" className="text-sm font-medium">
            Confirm new password
          </label>
          <Input
            id="reset-confirm"
            name="confirm"
            type={showPassword ? 'text' : 'password'}
            placeholder="••••••••"
            autoComplete="new-password"
            onChange={() => setFieldErrors((p) => ({ ...p, confirm: undefined }))}
          />
          {fieldErrors.confirm && <p className="text-xs text-destructive">{fieldErrors.confirm}</p>}
        </div>

        <Button type="submit" className="w-full" disabled={isLoading}>
          {isLoading ? (
            <>
              <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Updating…
            </>
          ) : (
            'Update password'
          )}
        </Button>
      </form>

      <p className="text-center text-sm text-muted-foreground">
        <Link
          to="/auth/login"
          search={{ redirect: undefined }}
          className="font-medium text-foreground underline-offset-4 hover:underline"
        >
          Back to sign in
        </Link>
      </p>
    </div>
  )
}
