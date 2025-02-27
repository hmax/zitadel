import { ChangeDetectionStrategy, Component, DestroyRef, OnInit, signal } from '@angular/core';
import { Router } from '@angular/router';
import { ToastService } from 'src/app/services/toast.service';
import { FormBuilder, FormControl, ValidatorFn } from '@angular/forms';
import { UserService } from 'src/app/services/user.service';
import { LanguagesService } from 'src/app/services/languages.service';
import { FeatureService } from 'src/app/services/feature.service';
import { Breadcrumb, BreadcrumbService, BreadcrumbType } from 'src/app/services/breadcrumb.service';
import { Location } from '@angular/common';
import {
  containsLowerCaseValidator,
  containsNumberValidator,
  containsSymbolValidator,
  containsUpperCaseValidator,
  emailValidator,
  minLengthValidator,
  passwordConfirmValidator,
  requiredValidator,
} from 'src/app/modules/form-field/validators/validators';
import { NewMgmtService } from 'src/app/services/new-mgmt.service';
import { defaultIfEmpty, defer, EMPTY, Observable, shareReplay } from 'rxjs';
import { catchError, filter, map, startWith } from 'rxjs/operators';
import { PasswordComplexityPolicy } from '@zitadel/proto/zitadel/policy_pb';
import { MessageInitShape } from '@bufbuild/protobuf';
import { AddHumanUserRequestSchema } from '@zitadel/proto/zitadel/user/v2/user_service_pb';
import { withLatestFromSynchronousFix } from '../../../../utils/withLatestFromSynchronousFix';

type PwdForm = ReturnType<UserCreateV2Component['buildPwdForm']>;
type AuthenticationFactor =
  | { factor: 'none' }
  | { factor: 'initialPassword'; form: PwdForm; policy: PasswordComplexityPolicy }
  | { factor: 'invitation' };

@Component({
  selector: 'cnsl-user-create-v2',
  templateUrl: './user-create-v2.component.html',
  styleUrls: ['./user-create-v2.component.scss'],
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class UserCreateV2Component implements OnInit {
  protected readonly userForm: ReturnType<typeof this.buildUserForm>;
  private readonly passwordComplexityPolicy$: Observable<PasswordComplexityPolicy>;
  protected readonly authenticationFactor$: Observable<AuthenticationFactor>;

  protected loading = signal(false);

  constructor(
    private router: Router,
    private readonly toast: ToastService,
    private readonly fb: FormBuilder,
    private readonly userService: UserService,
    public readonly langSvc: LanguagesService,
    private readonly featureService: FeatureService,
    private readonly destroyRef: DestroyRef,
    private readonly breadcrumbService: BreadcrumbService,
    private readonly newMgmtService: NewMgmtService,
    protected readonly location: Location,
  ) {
    this.userForm = this.buildUserForm();

    this.passwordComplexityPolicy$ = this.getPasswordComplexityPolicy().pipe(shareReplay({ refCount: true, bufferSize: 1 }));
    this.authenticationFactor$ = this.getAuthenticationFactor(this.userForm, this.passwordComplexityPolicy$);
  }

  ngOnInit(): void {
    this.breadcrumbService.setBreadcrumb([
      new Breadcrumb({
        type: BreadcrumbType.ORG,
        routerLink: ['/org'],
      }),
    ]);
  }

  private getAuthenticationFactor(
    userForm: typeof this.userForm,
    passwordComplexityPolicy$: Observable<PasswordComplexityPolicy>,
  ): Observable<AuthenticationFactor> {
    const pwdForm$ = passwordComplexityPolicy$.pipe(
      defaultIfEmpty(undefined),
      map((policy) => this.buildPwdForm(policy)),
    );

    return userForm.controls.authenticationFactor.valueChanges.pipe(
      startWith(userForm.controls.authenticationFactor.value),
      withLatestFromSynchronousFix(pwdForm$, passwordComplexityPolicy$),
      map(([factor, form, policy]) => {
        if (factor === 'initialPassword') {
          return { factor, form, policy };
        }
        return { factor };
      }),
    );
  }

  public buildUserForm() {
    return this.fb.group({
      email: new FormControl('', { nonNullable: true, validators: [requiredValidator, emailValidator] }),
      username: new FormControl('', { nonNullable: true, validators: [requiredValidator, minLengthValidator(2)] }),
      givenName: new FormControl('', { nonNullable: true, validators: [requiredValidator] }),
      familyName: new FormControl('', { nonNullable: true, validators: [requiredValidator] }),
      nickName: new FormControl('', { nonNullable: true }),
      emailVerified: new FormControl(false, { nonNullable: true }),
      authenticationFactor: new FormControl<AuthenticationFactor['factor']>('none', { nonNullable: true }),
    });
  }

  private buildPwdForm(policy: PasswordComplexityPolicy | undefined) {
    const validators: ValidatorFn[] = [requiredValidator];
    if (policy?.minLength) {
      validators.push(minLengthValidator(Number(policy.minLength)));
    }
    if (policy?.hasLowercase) {
      validators.push(containsLowerCaseValidator);
    }
    if (policy?.hasUppercase) {
      validators.push(containsUpperCaseValidator);
    }
    if (policy?.hasNumber) {
      validators.push(containsNumberValidator);
    }
    if (policy?.hasSymbol) {
      validators.push(containsSymbolValidator);
    }
    return this.fb.group({
      password: new FormControl('', { nonNullable: true, validators }),
      confirmPassword: new FormControl('', {
        nonNullable: true,
        validators: [requiredValidator, passwordConfirmValidator()],
      }),
    });
  }

  private getPasswordComplexityPolicy() {
    return defer(() => this.newMgmtService.getPasswordComplexityPolicy()).pipe(
      map(({ policy }) => policy),
      filter(Boolean),
      catchError((error) => {
        this.toast.showError(error);
        return EMPTY;
      }),
    );
  }

  protected async createUserV2(authenticationFactor: AuthenticationFactor) {
    this.loading.set(true);
    const userValues = this.userForm.getRawValue();
    const humanReq: MessageInitShape<typeof AddHumanUserRequestSchema> = {
      username: userValues.username,
      profile: {
        givenName: userValues.givenName,
        familyName: userValues.familyName,
        nickName: userValues.nickName,
      },
      email: {
        email: userValues.email,
        verification: {
          case: 'isVerified',
          value: userValues.emailVerified,
        },
      },
    };
    if (authenticationFactor.factor === 'initialPassword') {
      const { password } = authenticationFactor.form.getRawValue();
      humanReq.passwordType = {
        case: 'password',
        value: {
          password,
        },
      };
    }
    try {
      const resp = await this.userService.addHumanUser(humanReq);
      if (authenticationFactor.factor === 'invitation') {
        await this.userService.createInviteCode({
          userId: resp.userId,
          verification: {
            case: 'sendCode',
            value: {},
          },
        });
      }
      this.toast.showInfo('USER.TOAST.CREATED', true);
      await this.router.navigate(['users', resp.userId], { queryParams: { new: true } });
    } catch (error) {
      this.toast.showError(error);
    } finally {
      this.loading.set(false);
    }
  }
}
